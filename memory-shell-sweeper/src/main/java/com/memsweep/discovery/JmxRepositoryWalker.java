package com.memsweep.discovery;

import com.memsweep.util.Reflect;

import javax.management.MBeanServer;
import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

/**
 * JDK 平台 MBeanServer 反射遍历器。
 *
 * 各容器都会把核心组件注册为 MBean：
 *   Tomcat   -> Catalina:type=Context,...（BaseModelMBean 包装）
 *   Jetty    -> org.eclipse.jetty.servlet:type=ServletHandler,...（ObjectMBean 包装）
 *   WebLogic -> com.bea: 域
 *
 * JDK 内部结构（com.sun.jmx.mbeanserver 命名空间，JDK 8~21 稳定）：
 *   JmxMBeanServer
 *     └─ mbsInterceptor (DefaultMBeanServerInterceptor)
 *          └─ repository (Repository)
 *               └─ domainMap: Map<domainName, Map<ObjectName, NamedObject>>
 *                    └─ NamedObject.getObject() -> 容器注册的 MBean 实例
 *
 * 标准 JMX API 只能拿到 ObjectInstance（类名+ObjectName），拿不到资源实例，
 * 因此必须反射进入这个内部结构；所有访问均有异常兜底，JDK 内部改版时降级为空结果。
 */
public final class JmxRepositoryWalker {

    private JmxRepositoryWalker() {}

    /** 遍历平台 MBeanServer 中所有已注册 MBean 的底层资源对象。 */
    public static List<Object> allManagedResources() {
        List<Object> out = new ArrayList<>();
        MBeanServer server;
        try {
            server = ManagementFactory.getPlatformMBeanServer();
        } catch (Exception e) {
            return out;
        }
        Object repository = locateRepository(server);
        if (repository != null) {
            collectFromRepository(repository, out);
        }
        return out;
    }

    private static Object locateRepository(MBeanServer server) {
        // 路径 1：server 自身就有 repository 字段（部分封装实现）
        Object repository = Reflect.getField(server, "repository");
        if (repository != null) {
            return repository;
        }
        // 路径 2：JmxMBeanServer -> mbsInterceptor -> repository（OpenJDK 标准结构）
        Object interceptor = Reflect.getField(server, "mbsInterceptor");
        if (interceptor != null) {
            repository = Reflect.getField(interceptor, "repository");
            if (repository != null) {
                return repository;
            }
        }
        // 路径 3：在 server 字段里按类型找 Repository
        for (var f : Reflect.allFields(server.getClass())) {
            if (f.getType().getSimpleName().contains("Repository")) {
                Object v = Reflect.getFieldOfType(server, f.getType());
                if (v != null) {
                    return v;
                }
            }
        }
        return null;
    }

    private static void collectFromRepository(Object repository, List<Object> out) {
        // OpenJDK Repository 的域表字段在不同版本叫 domainTb / domainMap / domainTlk
        Object domainMap = Reflect.getField(repository, "domainTb");
        if (domainMap == null) {
            domainMap = Reflect.getField(repository, "domainMap");
        }
        if (domainMap == null) {
            domainMap = Reflect.getField(repository, "domainTlk");
        }
        if (!(domainMap instanceof Map<?, ?> map)) {
            return;
        }
        for (Object domainObj : map.values()) {
            if (domainObj instanceof Map<?, ?> inner) {
                for (Object named : inner.values()) {
                    Object resource = extractNamedResource(named);
                    if (resource != null) {
                        out.add(resource);
                    }
                }
            }
        }
    }

    private static Object extractNamedResource(Object namedObject) {
        if (namedObject == null) {
            return null;
        }
        // com.sun.jmx.mbeanserver.NamedObject.getObject()
        if (namedObject.getClass().getSimpleName().equals("NamedObject")) {
            Object r = Reflect.invoke(namedObject, "getObject");
            if (r != null) {
                return unwrapModelMBean(r);
            }
        }
        Object r = Reflect.getField(namedObject, "resource");
        if (r != null) {
            return unwrapModelMBean(r);
        }
        return unwrapModelMBean(namedObject);
    }

    /**
     * 解包 MBean 包装，取回被管理的真实资源：
     *   - Jetty ObjectMBean 体系（HolderMBean/FilterMappingMBean/...）的 getManagedObject()
     *   - com.sun.jmx.mbeanserver.StandardMBeanSupport.getResource()（JDK 标准 MBean 的实际包装）
     *   - javax.management.StandardMBean.getImplementation()
     *   - Tomcat BaseModelMBean 的 managedResource 字段
     * 基于方法存在性而非类名判断，覆盖各容器 MBean 的全部子类。
     */
    private static Object unwrapModelMBean(Object mbean) {
        if (mbean == null) {
            return null;
        }
        String cn = mbean.getClass().getName();

        // Jetty ObjectMBean 及其众多子类（getManagedObject 是公共方法）
        if (Reflect.findMethodByName(mbean.getClass(), "getManagedObject").isPresent()) {
            Object managed = Reflect.invoke(mbean, "getManagedObject");
            if (managed != null) {
                return managed;
            }
        }
        // JDK 标准 MBean 包装（平台里普通 Standard MBean 的实际形态）
        if (cn.contains("StandardMBeanSupport") || cn.contains("StandardMBean")) {
            Object r = Reflect.invoke(mbean, "getResource");
            if (r != null) {
                return r;
            }
            r = Reflect.invoke(mbean, "getImplementation");
            if (r != null) {
                return r;
            }
        }
        if (cn.contains("ModelMBean") || cn.contains("BaseModelMBean")) {
            Object managed = Reflect.getField(mbean, "managedResource");
            if (managed != null) {
                return managed;
            }
            managed = Reflect.getField(mbean, "resource");
            if (managed != null) {
                return managed;
            }
        }
        if (cn.contains("ObjectMBean")) {
            Object managed = Reflect.getField(mbean, "_managed");
            if (managed != null) {
                return managed;
            }
        }
        return mbean;
    }

    /** 按类型简单名在 MBean 资源里筛选（适配 javax/jakarta 不同包名）。 */
    public static List<Object> filterBySimpleClassName(String simpleName) {
        return filter(o -> o != null && o.getClass().getSimpleName().equals(simpleName));
    }

    public static List<Object> filter(Predicate<Object> p) {
        List<Object> out = new ArrayList<>();
        Set<Integer> seen = new LinkedHashSet<>();
        for (Object o : allManagedResources()) {
            if (o != null && p.test(o) && seen.add(System.identityHashCode(o))) {
                out.add(o);
            }
        }
        return out;
    }
}
