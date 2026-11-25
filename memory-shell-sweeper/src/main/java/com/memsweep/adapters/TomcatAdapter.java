package com.memsweep.adapters;

import com.memsweep.core.ContainerAdapter;
import com.memsweep.core.DiscoveryContext;
import com.memsweep.discovery.JmxRepositoryWalker;
import com.memsweep.discovery.LoadedClassDetector;
import com.memsweep.discovery.ThreadRootWalker;
import com.memsweep.model.ComponentRecord;
import com.memsweep.util.Reflect;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Apache Tomcat（含 Spring Boot 内嵌 Tomcat、Tomcat 9 javax 与 Tomcat 10+ jakarta）适配器。
 *
 * 枚举面：
 *   StandardContext.filterDefs  (Map<String, FilterDef>)      —— 全部 Filter 定义
 *   StandardContext.filterMaps  (FilterMap[])                 —— URL 映射
 *   StandardContext.children    (Container[] = Wrapper)       —— Servlet
 *   applicationEventListeners / applicationLifecycleListeners —— Listener
 *
 * 摘除面（使用容器自身公共方法，遵守容器内部锁）：
 *   StandardContext.removeFilterMap(FilterMap)
 *   StandardContext.removeFilterDef(FilterDef)
 *   filterConfigs.remove(name) 后宽限等待，再 Filter.destroy()
 *   StandardContext.removeChild(wrapper)                      —— Servlet
 *   removeApplicationEventListener / removeApplicationLifecycleListener —— Listener
 */
public class TomcatAdapter implements ContainerAdapter {

    public static final String NAME = "tomcat";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public boolean isPresent(DiscoveryContext ctx) {
        return LoadedClassDetector.anyLoaded(ctx.getInstrumentation(),
                "org.apache.catalina.core.StandardContext",
                "org.apache.catalina.startup.Tomcat",
                "org.apache.catalina.core.StandardServer");
    }

    @Override
    public void discover(DiscoveryContext ctx) {
        for (Object context : findContexts()) {
            discoverFilters(ctx, context);
            discoverServlets(ctx, context);
            discoverListeners(ctx, context);
        }
    }

    private List<Object> findContexts() {
        List<Object> contexts = new ArrayList<>();
        Set<Integer> seen = new LinkedHashSet<>();
        // 路径 1：MBean 仓库（独立 Tomcat / 开启 JMX 的内嵌实例）
        for (Object o : JmxRepositoryWalker.filterBySimpleClassName("StandardContext")) {
            if (seen.add(System.identityHashCode(o))) {
                contexts.add(o);
            }
        }
        // 路径 2：线程根对象图（无 JMX 的内嵌 Tomcat）
        for (Object o : ThreadRootWalker.findBySimpleClassName("StandardContext")) {
            if (seen.add(System.identityHashCode(o))) {
                contexts.add(o);
            }
        }
        // 路径 3：从 Acceptor/Connector 沿容器父子链显式下行（内嵌 Tomcat 主路径）
        for (Object o : com.memsweep.discovery.TomcatRootLocator.findStandardContexts()) {
            if (seen.add(System.identityHashCode(o))) {
                contexts.add(o);
            }
        }
        return contexts;
    }

    // ---------------------------------------------------------------- Filters

    private void discoverFilters(DiscoveryContext ctx, Object context) {
        Object filterDefs = Reflect.getField(context, "filterDefs");
        if (!(filterDefs instanceof java.util.Map<?, ?> defs)) {
            return;
        }
        Object filterMaps = filterMapsArray(context);
        Object filterConfigs = Reflect.getField(context, "filterConfigs");
        for (Object def : defs.values()) {
            String filterName = (String) Reflect.invoke(def, "getFilterName");
            Object filterInstance = Reflect.invoke(def, "getFilter");
            // ApplicationFilterConfig 构造后会把 Filter 实例从 FilterDef 接管，
            // 需从 filterConfigs 兜底取回（运行期注册的内存马正是这种形态）
            if (filterInstance == null && filterConfigs instanceof java.util.Map<?, ?> cfg) {
                Object config = cfg.get(filterName);
                if (config != null) {
                    // 先试公共/包级 getFilter()（可能触发懒初始化），再直接读私有字段
                    filterInstance = Reflect.invoke(config, "getFilter");
                    if (filterInstance == null) {
                        filterInstance = Reflect.getField(config, "filter");
                    }
                    // 最后回退到 config 持有的 FilterDef
                    if (filterInstance == null) {
                        Object innerDef = Reflect.invoke(config, "getFilterDef");
                        if (innerDef != null) {
                            filterInstance = Reflect.invoke(innerDef, "getFilter");
                        }
                    }
                }
            }
            Class<?> filterClass = classOfFilter(context, def, filterInstance);

            ComponentRecord r = new ComponentRecord(nextId(ctx, ComponentRecord.Kind.FILTER, filterName));
            r.setKind(ComponentRecord.Kind.FILTER);
            r.setComponentName(filterName);
            r.setDiscoveredBy(NAME);
            r.setUrlMappings(extractUrlPatterns(filterMaps, filterName));
            if (r.getUrlMappings().stream().anyMatch(p -> p.equals("/*") || p.equals("/") || p.startsWith("/*"))) {
                r.addSignal("BROAD_URL_MAPPING");
            }

            ctx.analyze(r, filterClass);
            ctx.registerIfNew(r, new TomcatHandle(context, def, filterMapsFor(filterMaps, filterName),
                    filterInstance, ComponentRecord.Kind.FILTER, filterName));
        }
    }

    private List<Object> filterMapsFor(Object filterMaps, String filterName) {
        List<Object> matched = new ArrayList<>();
        if (filterMaps instanceof Object[] arr) {
            for (Object fm : arr) {
                Object n = Reflect.invoke(fm, "getFilterName");
                if (filterName.equals(n)) {
                    matched.add(fm);
                }
            }
        }
        return matched;
    }

    /**
     * 取得 FilterMap 数组，兼容三代内部结构：
     *   1. 公共 findFilterMaps()（推荐，跨版本稳定）
     *   2. 新版 ContextFilterMaps 包装对象的 array 字段 / asArray()
     *   3. 旧版 StandardContext 上的裸 FilterMap[] 字段
     */
    private Object filterMapsArray(Object context) {
        Object viaApi = Reflect.invoke(context, "findFilterMaps");
        if (viaApi instanceof Object[] apiArr) {
            return apiArr;
        }
        Object raw = Reflect.getField(context, "filterMaps");
        if (raw instanceof Object[] rawArr) {
            return rawArr;
        }
        if (raw != null) {
            Object asArray = Reflect.invoke(raw, "asArray");
            if (asArray instanceof Object[] a) {
                return a;
            }
            Object inner = Reflect.getField(raw, "array");
            if (inner instanceof Object[] b) {
                return b;
            }
        }
        return new Object[0];
    }

    private List<String> extractUrlPatterns(Object filterMaps, String filterName) {
        List<String> patterns = new ArrayList<>();
        if (filterMaps instanceof Object[] arr) {
            for (Object fm : arr) {
                Object n = Reflect.invoke(fm, "getFilterName");
                if (filterName.equals(n)) {
                    Object urls = Reflect.invoke(fm, "getURLPatterns");
                    if (urls instanceof String[] sa) {
                        patterns.addAll(java.util.Arrays.asList(sa));
                    }
                }
            }
        }
        return patterns;
    }

    private Class<?> classOfFilter(Object context, Object filterDef, Object filterInstance) {
        if (filterInstance != null) {
            return filterInstance.getClass();
        }
        // 尚未实例化的 FilterDef 只有 className 字符串，尝试用容器类加载器加载
        String className = (String) Reflect.invoke(filterDef, "getFilterClass");
        if (className == null) {
            return null;
        }
        Object loader = Reflect.invoke(context, "getLoader");
        ClassLoader cl = null;
        if (loader != null) {
            cl = (ClassLoader) Reflect.invoke(loader, "getClassLoader");
        }
        if (cl == null) {
            cl = Thread.currentThread().getContextClassLoader();
        }
        try {
            return Class.forName(className, false, cl);
        } catch (Throwable t) {
            return null;
        }
    }

    // -------------------------------------------------------------- Servlets

    private void discoverServlets(DiscoveryContext ctx, Object context) {
        Object children = Reflect.invoke(context, "findChildren");
        if (!(children instanceof Object[] wrappers)) {
            return;
        }
        for (Object wrapper : wrappers) {
            String name = (String) Reflect.invoke(wrapper, "getName");
            String servletClassName = (String) Reflect.invoke(wrapper, "getServletClass");
            Object servletInstance = safeServletInstance(wrapper);
            Class<?> servletClass = servletInstance != null ? servletInstance.getClass()
                    : forName(servletClassName, context);

            ComponentRecord r = new ComponentRecord(nextId(ctx, ComponentRecord.Kind.SERVLET, name));
            r.setKind(ComponentRecord.Kind.SERVLET);
            r.setComponentName(name);
            r.setDiscoveredBy(NAME);
            Object mappings = Reflect.invoke(wrapper, "findMappings");
            if (mappings instanceof String[] sa && sa.length > 0) {
                r.setUrlMappings(java.util.Arrays.asList(sa));
            } else {
                Object all = Reflect.invoke(context, "findServletMappings");
                if (all instanceof String[] allSa) {
                    r.setUrlMappings(java.util.Arrays.asList(allSa));
                }
            }
            ctx.analyze(r, servletClass);
            ctx.registerIfNew(r, new TomcatHandle(context, wrapper, null,
                    servletInstance, ComponentRecord.Kind.SERVLET, name));
        }
    }

    private Object safeServletInstance(Object wrapper) {
        try {
            return Reflect.invoke(wrapper, "getServlet");
        } catch (Exception e) {
            return null;
        }
    }

    private Class<?> forName(String className, Object context) {
        if (className == null) {
            return null;
        }
        Object loader = Reflect.invoke(context, "getLoader");
        ClassLoader cl = loader == null ? Thread.currentThread().getContextClassLoader()
                : (ClassLoader) Reflect.invoke(loader, "getClassLoader");
        try {
            return Class.forName(className, false, cl);
        } catch (Throwable t) {
            return null;
        }
    }

    // -------------------------------------------------------------- Listeners

    private void discoverListeners(DiscoveryContext ctx, Object context) {
        inspectListenerList(ctx, context,
                (List<?>) Reflect.getField(context, "applicationEventListeners"));
        inspectListenerList(ctx, context,
                (List<?>) Reflect.getField(context, "applicationLifecycleListeners"));
    }

    private void inspectListenerList(DiscoveryContext ctx, Object context, List<?> listeners) {
        if (listeners == null) {
            return;
        }
        for (Object listener : new ArrayList<>(listeners)) {
            String listenerName = listener.getClass().getSimpleName();
            ComponentRecord r = new ComponentRecord(nextId(ctx, ComponentRecord.Kind.LISTENER, listenerName));
            r.setKind(ComponentRecord.Kind.LISTENER);
            r.setComponentName(listenerName);
            r.setDiscoveredBy(NAME);
            ctx.analyze(r, listener.getClass());
            ctx.registerIfNew(r, new TomcatHandle(context, null, null,
                    listener, ComponentRecord.Kind.LISTENER, r.getComponentName()));
        }
    }

    // ---------------------------------------------------------------- Removal

    @Override
    public RemovalOutcome remove(DiscoveryContext ctx, String recordId) {
        Object handle = ctx.getRemovalHandle(recordId);
        if (!(handle instanceof TomcatHandle h)) {
            return RemovalOutcome.unsupported("no tomcat removal handle for " + recordId);
        }
        if (ctx.getOptions().getMode() == com.memsweep.core.SweepOptions.Mode.DRY_RUN) {
            return RemovalOutcome.ok("[dry-run] would remove " + h.kind + " " + h.name);
        }
        try {
            switch (h.kind) {
                case FILTER:
                    return removeFilter(ctx, h);
                case SERVLET:
                    return removeServlet(h);
                case LISTENER:
                    return removeListener(h);
                default:
                    return RemovalOutcome.unsupported("unsupported kind " + h.kind);
            }
        } catch (Exception e) {
            return RemovalOutcome.failed(e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    /**
     * Tomcat Filter 摘除（标准内存马场景）：
     * 1. removeFilterMap：先摘映射，新请求的过滤器链不再包含该 Filter
     * 2. removeFilterDef：摘定义
     * 3. 反射移除 filterConfigs 中的配置项
     * 4. 宽限等待：让已构建 FilterChain 的在途请求走完
     * 5. 调用 Filter.destroy() 释放资源；destroy 失败不回滚注册表
     */
    private RemovalOutcome removeFilter(DiscoveryContext ctx, TomcatHandle h) {
        Object context = h.context;
        // 步骤 1：先摘除映射（容器方法内部对 filterMaps 加锁）。
        // 摘除时重新收集当前映射，避免发现到摘除之间数组被容器重建导致句柄过期。
        List<Object> liveMaps = new ArrayList<>();
        Object currentMaps = filterMapsArray(context);
        if (currentMaps instanceof Object[] arr) {
            for (Object fm : arr) {
                if (h.name.equals(Reflect.invoke(fm, "getFilterName"))) {
                    liveMaps.add(fm);
                }
            }
        }
        for (Object fm : liveMaps) {
            Reflect.invoke(context, "removeFilterMap", fm);
        }
        // 步骤 2：摘定义（内部对 filterDefs 加锁并触发容器事件）
        Reflect.invoke(context, "removeFilterDef", h.filterDef);
        // 步骤 3：清理 filterConfigs
        Object filterConfigs = Reflect.getField(context, "filterConfigs");
        if (filterConfigs instanceof java.util.Map<?, ?> cfg) {
            cfg.remove(h.name);
        }
        // 步骤 4：宽限等待在途请求
        sleep(ctx.getOptions().getGracePeriodMs());
        // 步骤 5：销毁实例
        if (h.componentInstance != null) {
            try {
                Reflect.invoke(h.componentInstance, "destroy");
            } catch (Exception e) {
                return RemovalOutcome.ok("deregistered; destroy() failed: " + e.getMessage());
            }
        }
        return RemovalOutcome.ok("filter '" + h.name + "' removed: " + liveMaps.size()
                + " mapping(s), filterDef and filterConfig deregistered");
    }

    /**
     * Tomcat Servlet 摘除：removeChild 触发 Wrapper 停止与 Mapper 反注册；
     * 在途请求仍持有其 Servlet 实例，不受影响。
     */
    private RemovalOutcome removeServlet(TomcatHandle h) {
        Reflect.invoke(h.context, "removeChild", h.filterDef);
        sleep(1000);
        if (h.componentInstance != null) {
            Reflect.invoke(h.componentInstance, "destroy");
        }
        return RemovalOutcome.ok("servlet wrapper '" + h.name + "' removed from context");
    }

    private RemovalOutcome removeListener(TomcatHandle h) {
        Object context = h.context;
        Object removed = Reflect.invoke(context, "removeApplicationEventListener", h.componentInstance);
        if (removed == null) {
            removed = Reflect.invoke(context, "removeApplicationLifecycleListener", h.componentInstance);
        }
        return RemovalOutcome.ok("listener '" + h.name + "' removed: " + removed);
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(Math.max(0, ms));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private String nextId(DiscoveryContext ctx, ComponentRecord.Kind kind, String name) {
        return ctx.stableId(NAME, kind, name);
    }

    /** 适配器私有摘除句柄，保留活动对象引用，不进入 JSON 报告。 */
    private static final class TomcatHandle {
        final Object context;
        final Object filterDef;
        final List<Object> filterMaps;
        final Object componentInstance;
        final ComponentRecord.Kind kind;
        final String name;

        TomcatHandle(Object context, Object filterDef, List<Object> filterMaps,
                     Object componentInstance, ComponentRecord.Kind kind, String name) {
            this.context = context;
            this.filterDef = filterDef;
            this.filterMaps = filterMaps == null ? new ArrayList<>() : filterMaps;
            this.componentInstance = componentInstance;
            this.kind = kind;
            this.name = name;
        }
    }
}
