package com.memsweep.adapters;

import com.memsweep.core.ContainerAdapter;
import com.memsweep.core.DiscoveryContext;
import com.memsweep.discovery.JmxRepositoryWalker;
import com.memsweep.discovery.LoadedClassDetector;
import com.memsweep.discovery.ThreadRootWalker;
import com.memsweep.model.ComponentRecord;
import com.memsweep.util.Reflect;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Eclipse Jetty（9.x javax / 10-11 jakarta / 12 ee 环境）适配器。
 *
 * 枚举面（ServletContextHandler 内部 ServletHandler）：
 *   _filters         FilterHolder[]       Filter 实例持有者
 *   _filterMappings  FilterMapping[]      名称与路径映射
 *   _servlets        ServletHolder[]      Servlet 持有者
 *   _servletMappings ServletMapping[]
 *
 * 摘除面：
 *   setFilterMappings / setFilters / setServlets / setServletMappings 重建数组，
 *   调用 updateMappings() 让变更生效；整个过程在 ServletHandler 实例锁内完成，
 *   Jetty 请求线程构建 FilterChain 时同样需要该锁，因此注册表切换对在途请求无影响
 *   （在途请求已经持有自己的 FilterChain 快照）。
 */
public class JettyAdapter implements ContainerAdapter {

    public static final String NAME = "jetty";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public boolean isPresent(DiscoveryContext ctx) {
        return LoadedClassDetector.anyLoaded(ctx.getInstrumentation(),
                "org.eclipse.jetty.servlet.ServletHandler",
                "org.eclipse.jetty.servlet.ServletContextHandler");
    }

    @Override
    public void discover(DiscoveryContext ctx) {
        for (Object handler : findServletHandlers()) {
            discoverFilters(ctx, handler);
            discoverServlets(ctx, handler);
        }
    }

    private List<Object> findServletHandlers() {
        List<Object> handlers = new ArrayList<>();
        Set<Integer> seen = new LinkedHashSet<>();
        for (Object o : JmxRepositoryWalker.filterBySimpleClassName("ServletHandler")) {
            if (seen.add(System.identityHashCode(o))) {
                handlers.add(o);
            }
        }
        for (Object o : ThreadRootWalker.findBySimpleClassName("ServletHandler")) {
            if (seen.add(System.identityHashCode(o))) {
                handlers.add(o);
            }
        }
        return handlers;
    }

    // ---------------------------------------------------------------- Filters

    private void discoverFilters(DiscoveryContext ctx, Object servletHandler) {
        // Jetty 9 字段为数组，Jetty 10+ 字段为 List；优先用公共 getter（恒返回数组）
        Object holders = Reflect.invoke(servletHandler, "getFilters");
        if (holders == null) {
            holders = Reflect.getField(servletHandler, "_filters");
        }
        Object mappings = Reflect.invoke(servletHandler, "getFilterMappings");
        if (mappings == null) {
            mappings = Reflect.getField(servletHandler, "_filterMappings");
        }
        List<Object> holderList = toList(holders);
        if (holderList.isEmpty()) {
            return;
        }
        for (Object holder : holderList) {
            String filterName = (String) Reflect.invoke(holder, "getName");
            Object filterInstance = Reflect.invoke(holder, "getFilter");
            Class<?> filterClass = filterInstance != null ? filterInstance.getClass()
                    : forName((String) Reflect.invoke(holder, "getClassName"));

            ComponentRecord r = new ComponentRecord(nextId(ctx, ComponentRecord.Kind.FILTER, filterName));
            r.setKind(ComponentRecord.Kind.FILTER);
            r.setComponentName(filterName);
            r.setDiscoveredBy(NAME);
            r.setUrlMappings(extractMappingPaths(mappings, filterName));
            if (r.getUrlMappings().stream().anyMatch(p -> p.equals("/*") || p.equals("/"))) {
                r.addSignal("BROAD_URL_MAPPING");
            }
            ctx.analyze(r, filterClass);
            ctx.registerIfNew(r, new JettyHandle(servletHandler, holder, null,
                    ComponentRecord.Kind.FILTER, filterName));
        }
    }

    /** 兼容数组与 List 两种字段形态，统一转为 List。 */
    private static List<Object> toList(Object o) {
        List<Object> out = new ArrayList<>();
        if (o == null) {
            return out;
        }
        if (o instanceof Object[] arr) {
            out.addAll(Arrays.asList(arr));
        } else if (o instanceof List<?> l) {
            out.addAll(l);
        }
        return out;
    }

    private List<String> extractMappingPaths(Object mappings, String filterName) {
        List<String> out = new ArrayList<>();
        for (Object m : toList(mappings)) {
            Object name = Reflect.invoke(m, "getFilterName");
            if (!filterName.equals(name)) {
                continue;
            }
            Object paths = Reflect.invoke(m, "getPathSpecs");
            if (paths instanceof List<?> l) {
                for (Object p : l) {
                    out.add(String.valueOf(p));
                }
            }
            Object specs = Reflect.invoke(m, "getPathSpecs");
            if (specs instanceof String[] sa) {
                out.addAll(Arrays.asList(sa));
            }
        }
        return out;
    }

    // -------------------------------------------------------------- Servlets

    private void discoverServlets(DiscoveryContext ctx, Object servletHandler) {
        Object holders = Reflect.invoke(servletHandler, "getServlets");
        if (holders == null) {
            holders = Reflect.getField(servletHandler, "_servlets");
        }
        for (Object holder : toList(holders)) {
            String servletName = (String) Reflect.invoke(holder, "getName");
            Object servletInstance = Reflect.invoke(holder, "getServlet");
            Class<?> servletClass = servletInstance != null ? servletInstance.getClass()
                    : forName((String) Reflect.invoke(holder, "getClassName"));

            ComponentRecord r = new ComponentRecord(nextId(ctx, ComponentRecord.Kind.SERVLET, servletName));
            r.setKind(ComponentRecord.Kind.SERVLET);
            r.setComponentName(servletName);
            r.setDiscoveredBy(NAME);
            ctx.analyze(r, servletClass);
            ctx.registerIfNew(r, new JettyHandle(servletHandler, holder, null,
                    ComponentRecord.Kind.SERVLET, servletName));
        }
    }

    private Class<?> forName(String className) {
        if (className == null) {
            return null;
        }
        try {
            return Class.forName(className, false, Thread.currentThread().getContextClassLoader());
        } catch (Throwable t) {
            return null;
        }
    }

    // ---------------------------------------------------------------- Removal

    @Override
    public RemovalOutcome remove(DiscoveryContext ctx, String recordId) {
        Object handle = ctx.getRemovalHandle(recordId);
        if (!(handle instanceof JettyHandle h)) {
            return RemovalOutcome.unsupported("no jetty removal handle for " + recordId);
        }
        if (ctx.getOptions().getMode() == com.memsweep.core.SweepOptions.Mode.DRY_RUN) {
            return RemovalOutcome.ok("[dry-run] would remove " + h.kind + " " + h.name);
        }
        synchronized (h.servletHandler) {
            try {
                if (h.kind == ComponentRecord.Kind.FILTER) {
                    return removeFilter(ctx, h);
                }
                if (h.kind == ComponentRecord.Kind.SERVLET) {
                    return removeServlet(ctx, h);
                }
                return RemovalOutcome.unsupported("unsupported kind " + h.kind);
            } catch (Exception e) {
                return RemovalOutcome.failed(e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
    }

    private RemovalOutcome removeFilter(DiscoveryContext ctx, JettyHandle h) throws Exception {
        Object handler = h.servletHandler;
        List<Object> oldHolders = toList(Reflect.invoke(handler, "getFilters"));
        if (oldHolders.isEmpty()) {
            oldHolders = toList(Reflect.getField(handler, "_filters"));
        }
        List<Object> oldMappings = toList(Reflect.invoke(handler, "getFilterMappings"));
        if (oldMappings.isEmpty()) {
            oldMappings = toList(Reflect.getField(handler, "_filterMappings"));
        }

        List<Object> newHolders = new ArrayList<>();
        for (Object o : oldHolders) {
            if (o != h.holder) {
                newHolders.add(o);
            }
        }
        List<Object> newMappings = new ArrayList<>();
        int removedMappings = 0;
        for (Object m : oldMappings) {
            if (h.name.equals(Reflect.invoke(m, "getFilterName"))) {
                removedMappings++;
            } else {
                newMappings.add(m);
            }
        }

        // 容器公共 API（setter 接收类型化数组）：先换 holder 再换映射，随后刷新内部链缓存
        Reflect.invoke(handler, "setFilters", (Object) toTypedArray(newHolders,
                "org.eclipse.jetty.servlet.FilterHolder"));
        Reflect.invoke(handler, "setFilterMappings", (Object) toTypedArray(newMappings,
                "org.eclipse.jetty.servlet.FilterMapping"));
        invokeUpdateMappings(handler);
        invalidateChainCache(handler);

        sleep(ctx.getOptions().getGracePeriodMs());
        Object filter = Reflect.invoke(h.holder, "getFilter");
        if (filter != null) {
            Reflect.invoke(filter, "destroy");
        }
        return RemovalOutcome.ok("filter '" + h.name + "' removed: holder + " + removedMappings
                + " mapping(s), chain cache invalidated");
    }

    private RemovalOutcome removeServlet(DiscoveryContext ctx, JettyHandle h) throws Exception {
        Object handler = h.servletHandler;
        List<Object> oldHolders = toList(Reflect.invoke(handler, "getServlets"));
        if (oldHolders.isEmpty()) {
            oldHolders = toList(Reflect.getField(handler, "_servlets"));
        }
        List<Object> oldMappings = toList(Reflect.invoke(handler, "getServletMappings"));
        if (oldMappings.isEmpty()) {
            oldMappings = toList(Reflect.getField(handler, "_servletMappings"));
        }

        List<Object> newHolders = new ArrayList<>();
        for (Object o : oldHolders) {
            if (o != h.holder) {
                newHolders.add(o);
            }
        }
        List<Object> newMappings = new ArrayList<>();
        for (Object m : oldMappings) {
            if (!h.name.equals(Reflect.invoke(m, "getServletName"))) {
                newMappings.add(m);
            }
        }
        Reflect.invoke(handler, "setServlets", (Object) toTypedArray(newHolders,
                "org.eclipse.jetty.servlet.ServletHolder"));
        Reflect.invoke(handler, "setServletMappings", (Object) toTypedArray(newMappings,
                "org.eclipse.jetty.servlet.ServletMapping"));
        invokeUpdateMappings(handler);
        invalidateChainCache(handler);

        sleep(ctx.getOptions().getGracePeriodMs());
        Object servlet = Reflect.invoke(h.holder, "getServlet");
        if (servlet != null) {
            Reflect.invoke(servlet, "destroy");
        }
        return RemovalOutcome.ok("servlet '" + h.name + "' removed from ServletHandler");
    }

    /** 按全限定类名构造类型化数组（setter 要求具体组件类型而非 Object[]）。 */
    private static Object[] toTypedArray(List<Object> list, String componentTypeFqcn) throws Exception {
        Class<?> type = Class.forName(componentTypeFqcn);
        Object[] arr = (Object[]) java.lang.reflect.Array.newInstance(type, list.size());
        for (int i = 0; i < list.size(); i++) {
            arr[i] = list.get(i);
        }
        return arr;
    }

    /** updateMappings 在部分 Jetty 版本是 protected，反射调用。 */
    private void invokeUpdateMappings(Object handler) {
        Reflect.findMethodByName(handler.getClass(), "updateMappings")
                .ifPresent(m -> Reflect.invokeMethod(m, handler));
    }

    /** 部分 Jetty 版本维护 _chainCache 字段，摘除后必须清空，否则旧链继续命中。 */
    private void invalidateChainCache(Object handler) {
        Object cache = Reflect.getField(handler, "_chainCache");
        if (cache instanceof java.util.Map<?, ?> map) {
            map.clear();
        }
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

    private static final class JettyHandle {
        final Object servletHandler;
        final Object holder;
        final Object mapping;
        final ComponentRecord.Kind kind;
        final String name;

        JettyHandle(Object servletHandler, Object holder, Object mapping,
                    ComponentRecord.Kind kind, String name) {
            this.servletHandler = servletHandler;
            this.holder = holder;
            this.mapping = mapping;
            this.kind = kind;
            this.name = name;
        }
    }
}
