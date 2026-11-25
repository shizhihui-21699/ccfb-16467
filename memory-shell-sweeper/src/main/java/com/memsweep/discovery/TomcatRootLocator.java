package com.memsweep.discovery;

import com.memsweep.util.Reflect;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Tomcat 专用根定位器。
 *
 * 内嵌 Tomcat 默认不向平台 MBeanServer 注册组件，而通用对象图深度遍历难以稳定覆盖
 * Acceptor → Endpoint → ProtocolHandler(Connector) → Service → Engine → Host → Context
 * 这条长引用链。本定位器从线程根里已可达的网络层对象（Acceptor/Poller/Endpoint/Connector）
 * 出发，沿 Tomcat 公共容器 API 显式下行到 StandardContext，路径短、确定性强。
 *
 * 全程反射、零编译依赖，且只沿容器相关类型行进，避免在大堆上全量遍历。
 */
public final class TomcatRootLocator {

    private TomcatRootLocator() {}

    public static List<Object> findStandardContexts() {
        List<Object> contexts = new ArrayList<>();
        Set<Integer> seen = new LinkedHashSet<>();

        // 种子：线程根可达的 Tomcat 网络层/连接器对象
        List<Object> seeds = ThreadRootWalker.find(o -> {
            if (o == null) {
                return false;
            }
            String n = o.getClass().getName();
            return n.equals("org.apache.tomcat.util.net.Acceptor")
                    || n.contains("Endpoint") && n.startsWith("org.apache.tomcat.util.net")
                    || n.equals("org.apache.catalina.connector.Connector")
                    || n.contains("CoyoteAdapter");
        });

        for (Object seed : seeds) {
            Object connector = toConnector(seed);
            if (connector == null) {
                continue;
            }
            Object service = Reflect.invoke(connector, "getService");
            if (service == null) {
                continue;
            }
            Object engine = Reflect.invoke(service, "getContainer");
            if (engine == null) {
                // StandardService 也可能通过 findEngines 暴露
                Object engines = Reflect.invoke(service, "findEngines");
                if (engines instanceof Object[] arr && arr.length > 0) {
                    engine = arr[0];
                }
            }
            collectContexts(engine, contexts, seen);
        }
        return contexts;
    }

    /** 把不同种子类型统一归一到 Connector。 */
    private static Object toConnector(Object seed) {
        String n = seed.getClass().getName();
        if (n.equals("org.apache.catalina.connector.Connector")) {
            return seed;
        }
        // Acceptor -> endpoint
        Object endpoint = n.equals("org.apache.tomcat.util.net.Acceptor")
                ? Reflect.getField(seed, "endpoint")
                : seed;
        if (endpoint == null) {
            return null;
        }
        // AbstractEndpoint -> handler(CoyoteAdapter) -> connector
        Object handler = Reflect.invoke(endpoint, "getHandler");
        if (handler == null) {
            handler = Reflect.getField(endpoint, "handler");
        }
        if (handler != null) {
            Object connector = Reflect.getField(handler, "connector");
            if (connector != null) {
                return connector;
            }
        }
        // 部分版本 endpoint 持有 protocolHandler，其再持有 connector
        Object proto = Reflect.getField(endpoint, "protocolHandler");
        if (proto != null) {
            Object connector = Reflect.getField(proto, "adapter");
            if (connector != null) {
                return Reflect.getField(connector, "connector");
            }
        }
        return null;
    }

    /** 沿 Container.findChildren 递归下行，收集所有 StandardContext。 */
    private static void collectContexts(Object container, List<Object> out, Set<Integer> seen) {
        if (container == null || !seen.add(System.identityHashCode(container))) {
            return;
        }
        String simple = container.getClass().getSimpleName();
        if (simple.equals("StandardContext")) {
            out.add(container);
            return; // Context 之下是 Wrapper，无需继续
        }
        Object children = Reflect.invoke(container, "findChildren");
        if (children instanceof Object[] arr) {
            for (Object child : arr) {
                collectContexts(child, out, seen);
            }
        }
    }
}
