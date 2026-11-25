package com.memsweep.unit;

import com.memsweep.core.ClassIntrospector;
import com.memsweep.core.Classifier;
import com.memsweep.model.ComponentRecord;
import com.memsweep.testkit.BenignBusinessFilter;
import com.memsweep.testkit.EvilMemoryFilter;
import com.memsweep.testkit.MemoryClassLoader;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/** 类来源取证与评分定级：内存定义类 vs 磁盘类。 */
class ClassIntrospectorTest {

    private final ClassIntrospector introspector =
            new ClassIntrospector(null, System.currentTimeMillis(), ClassIntrospector.DEFAULT_ALLOW_PATTERNS);
    private final Classifier classifier = new Classifier(introspector);

    @Test
    void memoryDefinedClass_hasNullCodeSourceAndInMemoryFlag() throws Exception {
        byte[] bytes = bytesOf(EvilMemoryFilter.class);
        MemoryClassLoader loader = new MemoryClassLoader(getClass().getClassLoader());
        Class<?> memClass = loader.defineFromBytes(EvilMemoryFilter.class.getName(), bytes);

        ComponentRecord r = new ComponentRecord("t-1");
        introspector.inspect(r, memClass);

        assertTrue(r.isInMemoryClass(), "defineClass 字节码定义的类应识别为内存类");
        assertEquals("null", r.getCodeSource(), "无 ProtectionDomain 时 codeSource 应为 null");
        assertTrue(r.getSignals().contains("NULL_CODESOURCE"));
        assertTrue(r.getSignals().contains("RUNTIME_REGISTERED"));
        assertTrue(r.getClassLoaderInfo().contains("MemoryClassLoader"),
                "类加载器信息应指向内存 loader: " + r.getClassLoaderInfo());
    }

    @Test
    void diskLoadedClass_isNotFlaggedInMemory() {
        ComponentRecord r = new ComponentRecord("t-2");
        introspector.inspect(r, BenignBusinessFilter.class);
        assertFalse(r.isInMemoryClass());
        assertNotEquals("null", r.getCodeSource());
        assertTrue(r.getCodeSource().startsWith("file:/"), "磁盘类 codeSource 应为 file: URL: " + r.getCodeSource());
    }

    @Test
    void memoryClassWithRuntimeExec_reachesMaliciousThreshold() throws Exception {
        byte[] bytes = bytesOf(EvilMemoryFilter.class);
        MemoryClassLoader loader = new MemoryClassLoader(getClass().getClassLoader());
        Class<?> memClass = loader.defineFromBytes(EvilMemoryFilter.class.getName(), bytes);

        ComponentRecord r = new ComponentRecord("t-3");
        introspector.inspect(r, memClass);
        r.addSignal("BYTECODE_CMD_API");
        r.addSignal("BYTECODE_RUNTIME_EXEC");
        classifier.classify(r);

        assertEquals(ComponentRecord.Verdict.MALICIOUS, r.getVerdict(),
                "内存类+命令执行特征必须达到 MALICIOUS: " + r.getSignals());
        assertTrue(classifier.removable(r));
    }

    @Test
    void benignDiskClass_isNormalAndNotRemovable() {
        ComponentRecord r = new ComponentRecord("t-4");
        introspector.inspect(r, BenignBusinessFilter.class);
        classifier.classify(r);
        assertEquals(ComponentRecord.Verdict.NORMAL, r.getVerdict());
        assertFalse(classifier.removable(r));
    }

    @Test
    void allowlistedDynamicClass_isDowngraded() {
        ComponentRecord r = new ComponentRecord("t-5");
        // 模拟白名单探针类（用一个真实存在的 JDK 代理类）
        Object proxy = java.lang.reflect.Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class[]{Runnable.class},
                (p, m, a) -> null);
        introspector.inspect(r, proxy.getClass());
        classifier.classify(r);
        assertNotEquals(ComponentRecord.Verdict.MALICIOUS, r.getVerdict(),
                "JDK 动态代理等白名单类不应定 MALICIOUS: " + r.getSignals());
    }

    private byte[] bytesOf(Class<?> c) throws IOException {
        String resource = c.getName().replace('.', '/') + ".class";
        try (var in = c.getClassLoader().getResourceAsStream(resource)) {
            assertNotNull(in);
            return in.readAllBytes();
        }
    }
}
