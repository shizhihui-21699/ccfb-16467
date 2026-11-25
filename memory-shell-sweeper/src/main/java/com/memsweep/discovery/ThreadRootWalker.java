package com.memsweep.discovery;

import com.memsweep.util.Reflect;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

/**
 * 线程根扫描器：从全部存活线程的 ThreadGroup / Thread.target(Runnable) 出发，
 * 寻找容器核心对象。嵌入式容器（Spring Boot 内嵌 Tomcat/Jetty）常常不注册 MBean，
 * 但其接受线程（Acceptor/SelectorThread）是可达的 GC Root。
 *
 * 需要 --add-opens=java.base/java.lang=ALL-UNNAMED（agent 运行在目标 JVM 内，
 * agentmain 加载时由 manifest 的 Launcher-Agent-Class 机制自动获得模块开放权限的场景除外，
 * 因此所有反射访问都做异常兜底）。
 */
public final class ThreadRootWalker {

    private ThreadRootWalker() {}

    public static List<Object> findBySimpleClassName(String simpleName) {
        return find(o -> o != null && o.getClass().getSimpleName().equals(simpleName));
    }

    public static List<Object> find(Predicate<Object> predicate) {
        List<Object> hits = new ArrayList<>();
        Set<Integer> seen = new LinkedHashSet<>();
        Set<Thread> threads = getAllThreads();
        for (Thread t : threads) {
            try {
                Object target = Reflect.getField(t, "target");
                if (target instanceof Runnable) {
                    walkObject(target, predicate, hits, seen, 0);
                }
                ThreadGroup g = t.getThreadGroup();
                if (g != null) {
                    walkObject(g, predicate, hits, seen, 0);
                }
            } catch (Exception ignored) {
            }
        }
        return hits;
    }

    private static Set<Thread> getAllThreads() {
        Set<Thread> out = new LinkedHashSet<>();
        try {
            long[] ids = ManagementFactory.getThreadMXBean().getAllThreadIds();
            ThreadInfo[] infos = ManagementFactory.getThreadMXBean().getThreadInfo(ids, 0);
            // ThreadInfo 只给名称，真正的 Thread 实例需要从根线程组枚举
            ThreadGroup root = rootGroup();
            int estimated = Math.max(ids.length * 2, 64);
            Thread[] slack = new Thread[estimated];
            int n = root.enumerate(slack, true);
            for (int i = 0; i < n; i++) {
                if (slack[i] != null) {
                    out.add(slack[i]);
                }
            }
        } catch (Exception e) {
            // 兜底：当前线程组
            ThreadGroup g = Thread.currentThread().getThreadGroup();
            Thread[] slack = new Thread[g.activeCount() * 2 + 8];
            int n = g.enumerate(slack, true);
            for (int i = 0; i < n; i++) {
                if (slack[i] != null) {
                    out.add(slack[i]);
                }
            }
        }
        return out;
    }

    private static ThreadGroup rootGroup() {
        ThreadGroup g = Thread.currentThread().getThreadGroup();
        while (g.getParent() != null) {
            g = g.getParent();
        }
        return g;
    }

    /** 有限深度的对象图遍历，避免在大型堆上失控。深度需覆盖
     *  Acceptor -> Endpoint -> CoyoteAdapter -> Connector -> Service -> Engine -> Host -> Context 链。 */
    private static void walkObject(Object obj, Predicate<Object> p, List<Object> hits,
                                   Set<Integer> seen, int depth) {
        if (obj == null || depth > 8) {
            return;
        }
        int id = System.identityHashCode(obj);
        if (!seen.add(id)) {
            return;
        }
        if (p.test(obj)) {
            hits.add(obj);
        }
        // 只深入容器相关对象，跳过 JDK 集合/数组的无限展开
        String cn = obj.getClass().getName();
        if (!shouldDescend(cn)) {
            return;
        }
        try {
            for (var f : Reflect.allFields(obj.getClass())) {
                if (f.getType().isPrimitive() || f.getType() == String.class) {
                    continue;
                }
                Object v = f.get(obj);
                if (v == null) {
                    continue;
                }
                if (v.getClass().isArray()) {
                    int len = java.lang.reflect.Array.getLength(v);
                    for (int i = 0; i < Math.min(len, 64); i++) {
                        Object e = java.lang.reflect.Array.get(v, i);
                        if (e != null && shouldDescend(e.getClass().getName())) {
                            walkObject(e, p, hits, seen, depth + 1);
                        }
                    }
                } else if (v instanceof java.util.Collection<?> col) {
                    int i = 0;
                    for (Object e : col) {
                        if (i++ >= 64) {
                            break;
                        }
                        if (e != null && shouldDescend(e.getClass().getName())) {
                            walkObject(e, p, hits, seen, depth + 1);
                        }
                    }
                } else if (v instanceof java.util.Map<?, ?> map) {
                    int i = 0;
                    for (Object e : map.values()) {
                        if (i++ >= 64) {
                            break;
                        }
                        if (e != null && shouldDescend(e.getClass().getName())) {
                            walkObject(e, p, hits, seen, depth + 1);
                        }
                    }
                } else if (shouldDescend(v.getClass().getName())) {
                    walkObject(v, p, hits, seen, depth + 1);
                }
            }
        } catch (Exception ignored) {
        }
    }

    private static boolean shouldDescend(String className) {
        if (className == null) {
            return false;
        }
        return className.startsWith("org.apache.catalina")
                || className.startsWith("org.apache.coyote")
                || className.startsWith("org.apache.tomcat")
                || className.startsWith("org.eclipse.jetty")
                || className.startsWith("io.undertow")
                || className.startsWith("weblogic")
                || className.startsWith("com.bea")
                || className.startsWith("org.springframework.boot.web.embedded")
                || className.startsWith("java.util.") // 容器内部集合
                ;
    }
}
