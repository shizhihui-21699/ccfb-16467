package com.memsweep.core;

import com.memsweep.model.ComponentRecord;

import java.lang.instrument.Instrumentation;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.List;

/**
 * 类来源取证器：判断一个组件类是磁盘加载还是内存中动态定义的。
 *
 * 典型内存马的类定义特征：
 *   1. {@link ProtectionDomain#getCodeSource()} 为 null，或 location 不是 file:/jar: URL
 *      （defineClass(byte[], ...) 单参/双参版本默认 protection domain 的 codeSource 为 null）
 *   2. 类名包含 '/'（hidden class）或 '$$'（字节码库动态生成）
 *   3. 由非常规 ClassLoader（内存型 URLClassLoader / 脚本引擎 loader）定义
 *   4. 类加载时间晚于 JVM 启动完成时间（运行期注册）
 */
public class ClassIntrospector {

    private final Instrumentation inst;
    private final long jvmStartMillis;
    private final List<String> allowPatterns;

    public ClassIntrospector(Instrumentation inst, long jvmStartMillis, List<String> allowPatterns) {
        this.inst = inst;
        this.jvmStartMillis = jvmStartMillis;
        this.allowPatterns = allowPatterns == null ? new ArrayList<>() : allowPatterns;
    }

    public long getJvmStartMillis() {
        return jvmStartMillis;
    }

    /** 对组件类做来源取证，把信号写入 record。 */
    public void inspect(ComponentRecord record, Class<?> componentClass) {
        if (componentClass == null) {
            record.addSignal("CLASS_UNRESOLVABLE");
            return;
        }
        record.setClassName(componentClass.getName());

        ClassLoader cl = componentClass.getClassLoader();
        record.setClassLoaderInfo(describeLoader(cl));
        record.setBootstrapLoaded(cl == null);

        ProtectionDomain pd = componentClass.getProtectionDomain();
        CodeSource cs = pd == null ? null : pd.getCodeSource();
        String csText = "null";
        if (cs != null && cs.getLocation() != null) {
            csText = cs.getLocation().toString();
        }
        record.setCodeSource(csText);

        boolean inMemory = isMemoryDefined(componentClass, cl, csText);
        record.setInMemoryClass(inMemory);
        if (inMemory) {
            record.addSignal("IN_MEMORY_CLASS_BYTES");
            // 内存定义的类只可能是运行期注册进来的
            record.addSignal("RUNTIME_REGISTERED");
        }
        if (cs == null || cs.getLocation() == null) {
            record.addSignal("NULL_CODESOURCE");
        } else if (!isDiskLocation(cs.getLocation().toString())) {
            record.addSignal("NON_DISK_CODESOURCE:" + cs.getLocation());
        }

        String name = componentClass.getName();
        if (name.contains("/") || name.endsWith("/hidden")) {
            record.setHiddenClass(true);
            record.addSignal("HIDDEN_CLASS");
        }
        if (java.lang.reflect.Proxy.isProxyClass(componentClass)) {
            record.setDynamicProxy(true);
            record.addSignal("JDK_DYNAMIC_PROXY");
        }
        if (name.contains("$$") || name.contains("$Proxy") || name.startsWith("jdk.proxy")) {
            record.addSignal("GENERATED_CLASS_NAME");
        }
        if (cl != null && isSuspiciousLoader(cl)) {
            record.addSignal("SUSPICIOUS_CLASSLOADER:" + cl.getClass().getName());
        }

        // 加载时间：Instrumentation 不直接暴露，按 ClassLoader 首次出现时间近似。
        long loadTime = approximateLoadTime(componentClass);
        record.setClassLoadTimestamp(loadTime);
        record.setJvmStartTime(jvmStartMillis);
        if (loadTime > 0 && jvmStartMillis > 0 && loadTime > jvmStartMillis + 15_000) {
            record.setLoadedAfterStartup(true);
            record.addSignal("LOADED_AFTER_STARTUP");
        }
    }

    /**
     * 内存定义判定。
     *
     * 核心证据：非启动类加载器 + CodeSource 为 null。defineClass(name,bytes,off,len)
     * 不提供 ProtectionDomain，JVM 赋予的域 codeSource 恒为 null——磁盘加载的类
     * （AppClassLoader/URLClassLoader/模块加载器）总会带 file:/jrt: 来源。
     *
     * 注意：不能用 cl.getResource(className) 回查来否决该结论，因为内存马常仿冒
     * 已存在的类名，父加载器可能从磁盘解析到同名资源，但那不是当前实例的字节码来源。
     * 资源回查只在 codeSource 非空但协议异常时作为辅助证据。
     */
    private boolean isMemoryDefined(Class<?> c, ClassLoader cl, String codeSourceText) {
        if (cl == null) {
            return false; // 启动类加载器加载的不可能是注入类
        }
        if ("null".equals(codeSourceText)) {
            // 白名单内的框架动态类（CGLIB/ByteBuddy/代理）降级为良性动态类
            return !isAllowlisted(c.getName());
        }
        if (!isDiskLocation(codeSourceText)) {
            return !isAllowlisted(c.getName());
        }
        return false;
    }

    public boolean isAllowlisted(String className) {
        if (className == null) {
            return false;
        }
        for (String p : allowPatterns) {
            if (className.contains(p)) {
                return true;
            }
        }
        return false;
    }

    private boolean isDiskLocation(String loc) {
        return loc.startsWith("file:/") || loc.startsWith("jar:file:/")
                || loc.startsWith("jrt:/") || loc.startsWith("resource:");
    }

    private boolean isSuspiciousLoader(ClassLoader cl) {
        String n = cl.getClass().getName();
        // 脚本/动态字节码加载器是内存马常用载体
        return n.contains("jdk.internal.loader.URLClassPath") == false
                && (n.contains("ScriptLoader") || n.contains("MemoryClassLoader")
                || n.contains("BytesClassLoader") || n.contains("DefineClassLoader")
                || n.contains("GroovyClassLoader") || n.contains("Nashorn"));
    }

    private String describeLoader(ClassLoader cl) {
        if (cl == null) {
            return "<bootstrap>";
        }
        return cl.getClass().getName() + '@' + Integer.toHexString(System.identityHashCode(cl));
    }

    /**
     * 近似加载时间：用 instrumentation 拿到所有已加载类，无法直接取时间戳，
     * 这里返回 -1 表示未知；真正的时间信号由各适配器在“注册时刻”补充，
     * 或通过 ClassLoader 对象的创建时间字段（部分容器有 startTime）近似。
     */
    private long approximateLoadTime(Class<?> c) {
        return -1;
    }

    public Instrumentation getInstrumentation() {
        return inst;
    }

    /** 已知良性的动态生成类前缀（监控探针、框架增强、JDK 代理等）。 */
    public static final List<String> DEFAULT_ALLOW_PATTERNS = List.of(
            "jdk.proxy", "$Proxy", "java.lang.reflect.Proxy",
            "com.sun.proxy", "jdk.internal.reflect",
            "org.springframework.cglib", "net.sf.cglib",
            "net.bytebuddy", "org.mockito", "groovy.lang",
            "com.alibaba.druid.support", // Druid 监控 Filter 常见
            "org.apache.tomcat.websocket",
            "org.eclipse.jetty.websocket",
            "io.micrometer", "io.opentelemetry", "co.elastic.apm",
            "com.newrelic", "org.glowroot", "datadog",
            "skywalking", "org.apache.skywalking",
            "pinpoint", "com.navercorp.pinpoint",
            "arms", "com.alibaba.arms",
            "$$Lambda", "$$FastClass", "$$Enhancer",
            "org.gradle", "worker.org.gradle"
    );
}
