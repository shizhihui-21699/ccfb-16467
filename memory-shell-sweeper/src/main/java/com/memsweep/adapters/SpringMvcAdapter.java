package com.memsweep.adapters;

import com.memsweep.core.ContainerAdapter;
import com.memsweep.core.DiscoveryContext;
import com.memsweep.discovery.LoadedClassDetector;
import com.memsweep.discovery.ThreadRootWalker;
import com.memsweep.model.ComponentRecord;
import com.memsweep.util.Reflect;

import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Spring MVC / Spring Boot 适配器，覆盖 Controller/RequestMapping 型内存马。
 *
 * 枚举面：
 *   RequestMappingHandlerMapping.handlerMethods (Map<RequestMappingInfo, HandlerMethod>)
 *   RequestMappingHandlerMapping.urlMap / pathPatternParser 相关映射
 *
 * 摘除面（Spring 公共 API）：
 *   RequestMappingHandlerMapping.unregisterHandlerMethod(handler, mapping)
 *   AbstractHandlerMethodMapping 的 registry 映射同步移除
 *
 * 该注册表面对请求线程由 ConcurrentHashMap 保证读一致性，摘除对在途请求无影响：
 * 已进入 HandlerMethod 的请求继续执行，新请求拿不到该映射返回 404。
 */
public class SpringMvcAdapter implements ContainerAdapter {

    public static final String NAME = "spring-mvc";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public boolean isPresent(DiscoveryContext ctx) {
        Instrumentation inst = ctx.getInstrumentation();
        return LoadedClassDetector.anyLoaded(inst,
                "org.springframework.web.servlet.mvc.method.RequestMappingInfo",
                "org.springframework.web.servlet.handler.AbstractHandlerMethodMapping");
    }

    @Override
    public void discover(DiscoveryContext ctx) {
        Set<Integer> seen = new LinkedHashSet<>();
        for (Object mapping : findHandlerMappings()) {
            if (!seen.add(System.identityHashCode(mapping))) {
                continue;
            }
            inspectHandlerMethods(ctx, mapping);
        }
    }

    private List<Object> findHandlerMappings() {
        // RequestMappingHandlerMapping 通常被 Spring 容器引用，从线程根可达的
        // ApplicationEvent/BeanFactory 对象图中按类型找
        return ThreadRootWalker.find(o ->
                o != null && o.getClass().getSimpleName().equals("RequestMappingHandlerMapping"));
    }

    private void inspectHandlerMethods(DiscoveryContext ctx, Object handlerMapping) {
        Object handlerMethods = Reflect.getField(handlerMapping, "handlerMethods");
        if (!(handlerMethods instanceof java.util.Map<?, ?> map)) {
            return;
        }
        for (var entry : map.entrySet()) {
            Object mappingInfo = entry.getKey();
            Object handlerMethod = entry.getValue();
            Object bean = Reflect.invoke(handlerMethod, "getBean");
            Class<?> handlerClass;
            if (bean != null) {
                handlerClass = bean.getClass();
            } else {
                Object beanType = Reflect.invoke(handlerMethod, "getBeanType");
                handlerClass = beanType instanceof Class<?> bc ? bc : null;
            }

            String handlerName = String.valueOf(Reflect.invoke(mappingInfo, "getName"));
            ComponentRecord r = new ComponentRecord(nextId(ctx, ComponentRecord.Kind.SPRING_HANDLER, handlerName));
            r.setKind(ComponentRecord.Kind.SPRING_HANDLER);
            r.setComponentName(handlerName);
            r.setDiscoveredBy(NAME);
            r.setUrlMappings(extractPatterns(mappingInfo));
            ctx.analyze(r, handlerClass);
            // 摘除句柄保留 handlerMapping + mappingInfo + handler
            Object[] handle = new Object[]{handlerMapping, mappingInfo, bean};
            ctx.registerIfNew(r, handle);
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> extractPatterns(Object mappingInfo) {
        List<String> out = new ArrayList<>();
        Object patterns = Reflect.invoke(mappingInfo, "getPatternValues");
        if (patterns instanceof Set<?> set) {
            for (Object p : set) {
                out.add(String.valueOf(p));
            }
        }
        return out;
    }

    @Override
    public RemovalOutcome remove(DiscoveryContext ctx, String recordId) {
        Object handle = ctx.getRemovalHandle(recordId);
        if (!(handle instanceof Object[] arr) || arr.length < 3) {
            return RemovalOutcome.unsupported("no spring-mvc removal handle for " + recordId);
        }
        if (ctx.getOptions().getMode() == com.memsweep.core.SweepOptions.Mode.DRY_RUN) {
            return RemovalOutcome.ok("[dry-run] would unregister RequestMapping handler " + recordId);
        }
        Object handlerMapping = arr[0];
        Object mappingInfo = arr[1];
        Object bean = arr[2];
        // Spring 公共注销方法（AbstractHandlerMethodMapping#unregisterHandlerMethod）
        Object result = Reflect.invoke(handlerMapping, "unregisterHandlerMethod", bean, mappingInfo);
        if (result == null && !methodExists(handlerMapping, "unregisterHandlerMethod")) {
            return RemovalOutcome.unsupported(
                    "当前 Spring 版本无 unregisterHandlerMethod 公共方法，建议升级或用网关封禁 URL");
        }
        return RemovalOutcome.ok("handler method unregistered from RequestMappingHandlerMapping; "
                + "在途请求继续执行，新请求返回 404");
    }

    private boolean methodExists(Object target, String name) {
        return Reflect.findMethodByName(target.getClass(), name).isPresent();
    }

    private String nextId(DiscoveryContext ctx, ComponentRecord.Kind kind, String name) {
        return ctx.stableId(NAME, kind, name);
    }
}
