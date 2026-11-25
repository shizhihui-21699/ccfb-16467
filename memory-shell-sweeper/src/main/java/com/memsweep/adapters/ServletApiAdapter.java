package com.memsweep.adapters;

import com.memsweep.core.ContainerAdapter;
import com.memsweep.core.DiscoveryContext;
import com.memsweep.discovery.JmxRepositoryWalker;
import com.memsweep.discovery.ThreadRootWalker;
import com.memsweep.model.ComponentRecord;
import com.memsweep.util.Reflect;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * 通用 Servlet 3+ 兜底适配器（Undertow / WebLogic / WebSphere / 其它兼容容器）。
 *
 * 通过两条与厂商无关的路径拿 ServletContext：
 *   1. JMX/线程根里找到的容器 Context 对象上反射调用 getServletContext()
 *   2. 直接按接口简单名 ServletContext 在对象图里找
 *
 * 再用标准 API getFilterRegistrations()/getServletRegistrations() 枚举。
 * Servlet 规范禁止启动完成后动态注销，因此本适配器只做发现与定级，不做摘除；
 * 摘除由各容器专用适配器承担。
 */
public class ServletApiAdapter implements ContainerAdapter {

    public static final String NAME = "servlet-api";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public boolean isPresent(DiscoveryContext ctx) {
        // 仅当存在 jakarta 或 javax 的 Servlet 类时启用
        for (Class<?> c : ctx.getInstrumentation().getAllLoadedClasses()) {
            String n = c.getName();
            if (n.equals("jakarta.servlet.ServletContext") || n.equals("javax.servlet.ServletContext")) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void discover(DiscoveryContext ctx) {
        Set<Integer> seen = new LinkedHashSet<>();
        for (Object sc : findServletContexts()) {
            if (!seen.add(System.identityHashCode(sc))) {
                continue;
            }
            inspectRegistrations(ctx, sc);
        }
    }

    private java.util.List<Object> findServletContexts() {
        java.util.List<Object> out = new java.util.ArrayList<>();
        Set<Integer> seen = new LinkedHashSet<>();
        // 路径 1：容器 context 对象上的 getServletContext()
        for (Object root : JmxRepositoryWalker.allManagedResources()) {
            tryServletContext(root, out, seen);
        }
        for (Object root : ThreadRootWalker.find(o ->
                o != null && o.getClass().getSimpleName().contains("Context"))) {
            tryServletContext(root, out, seen);
        }
        // 路径 2：对象图中直接实现 ServletContext 接口的对象
        for (Object o : ThreadRootWalker.find(this::isServletContext)) {
            if (seen.add(System.identityHashCode(o))) {
                out.add(o);
            }
        }
        return out;
    }

    private boolean isServletContext(Object o) {
        for (Class<?> c : o.getClass().getInterfaces()) {
            if (c.getSimpleName().equals("ServletContext")) {
                return true;
            }
        }
        return false;
    }

    private void tryServletContext(Object containerContext, java.util.List<Object> out, Set<Integer> seen) {
        Object sc = Reflect.invoke(containerContext, "getServletContext");
        if (sc != null && seen.add(System.identityHashCode(sc))) {
            out.add(sc);
        }
    }

    @SuppressWarnings("unchecked")
    private void inspectRegistrations(DiscoveryContext ctx, Object servletContext) {
        Object filterRegs = Reflect.invoke(servletContext, "getFilterRegistrations");
        if (filterRegs instanceof Map<?, ?> map) {
            for (Object entry : map.entrySet()) {
                Map.Entry<String, Object> e = (Map.Entry<String, Object>) entry;
                Object reg = e.getValue();
                String className = (String) Reflect.invoke(reg, "getClassName");
                Class<?> clazz = forName(className);
                ComponentRecord r = new ComponentRecord(nextId(ctx, ComponentRecord.Kind.FILTER, e.getKey()));
                r.setKind(ComponentRecord.Kind.FILTER);
                r.setComponentName(e.getKey());
                r.setDiscoveredBy(NAME);
                ctx.analyze(r, clazz);
                ctx.registerIfNew(r, null); // 无摘除句柄：只读适配器
            }
        }
        Object servletRegs = Reflect.invoke(servletContext, "getServletRegistrations");
        if (servletRegs instanceof Map<?, ?> map) {
            for (Object entry : map.entrySet()) {
                Map.Entry<String, Object> e = (Map.Entry<String, Object>) entry;
                Object reg = e.getValue();
                String className = (String) Reflect.invoke(reg, "getClassName");
                Class<?> clazz = forName(className);
                ComponentRecord r = new ComponentRecord(nextId(ctx, ComponentRecord.Kind.SERVLET, e.getKey()));
                r.setKind(ComponentRecord.Kind.SERVLET);
                r.setComponentName(e.getKey());
                r.setDiscoveredBy(NAME);
                ctx.analyze(r, clazz);
                ctx.registerIfNew(r, null);
            }
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

    @Override
    public RemovalOutcome remove(DiscoveryContext ctx, String recordId) {
        return RemovalOutcome.unsupported(
                "Servlet 规范不提供启动后的标准注销 API；请使用对应容器的专用适配器摘除");
    }

    private String nextId(DiscoveryContext ctx, ComponentRecord.Kind kind, String name) {
        return ctx.stableId(NAME, kind, name);
    }
}
