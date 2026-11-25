package com.memsweep.core;

import com.memsweep.model.ComponentRecord;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.List;

/**
 * 字节码取证探针：通过一次性 retransformation 从 JVM 内部取回类的原始字节，
 * 在常量池/字节序列层面搜索命令执行相关 API 引用。
 *
 * 不做完整字节码解析，只做 UTF-8 常量串扫描，足够覆盖内存马最常用的调用：
 * Runtime.exec / ProcessBuilder / javax.script / MethodHandles.Lookup#defineHiddenClass 等。
 * 扫描完成后立即注销 transformer，不改变任何类的字节码（返回 null）。
 */
public class BytecodeProbe {

    /**
     * 命令执行/脚本引擎特征串，命中即强信号。
     * 刻意排除 HttpServletRequest 等纯 Servlet API——它们在几乎所有 Web 组件中都出现，
     * 没有区分度，会把正常业务组件误判为内存马。
     */
    private static final String[] CMD_PATTERNS = {
            "java/lang/Runtime",
            "exec",
            "java/lang/ProcessBuilder",
            "javax/script/ScriptEngine",
            "javax/script/ScriptEngineManager",
            "jdk/nashorn",
            "org/codehaus/groovy/runtime",
            "defineHiddenClass",
            "java/lang/invoke/MethodHandles",
            "com/opensymphony/xwork2",
            "ognl/Ognl",
            "mvel",
            "bsh/Interpreter"
    };

    private static final String[] RUNTIME_EXEC_PATTERNS = {
            "java/lang/Runtime", "java/lang/ProcessBuilder"
    };

    private static final String[] SCRIPT_PATTERNS = {
            "javax/script/ScriptEngine", "jdk/nashorn", "groovy/runtime",
            "bsh/Interpreter", "ognl/Ognl"
    };

    private final Instrumentation inst;

    public BytecodeProbe(Instrumentation inst) {
        this.inst = inst;
    }

    /** 对单个类做字节码扫描，把命中信号写入 record；失败不抛出。 */
    public void probe(ComponentRecord record, Class<?> target) {
        if (target == null || !inst.isModifiableClass(target)) {
            record.addSignal("BYTECODE_SCAN_UNAVAILABLE");
            return;
        }
        final byte[][] holder = new byte[1][];
        ClassFileTransformer t = new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                    ProtectionDomain pd, byte[] classfileBuffer) {
                if (classBeingRedefined == target) {
                    holder[0] = classfileBuffer.clone();
                }
                return null; // 永不修改字节码
            }
        };
        try {
            inst.addTransformer(t, true);
            inst.retransformClasses(target);
        } catch (Exception e) {
            record.addSignal("BYTECODE_SCAN_FAILED:" + e.getClass().getSimpleName());
            return;
        } finally {
            inst.removeTransformer(t);
        }
        byte[] bytes = holder[0];
        if (bytes == null) {
            record.addSignal("BYTECODE_SCAN_NO_BYTES");
            return;
        }
        String text = extractAsciiStrings(bytes);
        List<String> hits = new ArrayList<>();
        for (String p : CMD_PATTERNS) {
            if (text.contains(p)) {
                hits.add(p);
            }
        }
        if (!hits.isEmpty()) {
            record.addSignal("BYTECODE_CMD_API");
            for (String h : hits) {
                record.addSignal("BYTECODE_HIT:" + h);
            }
        }
        for (String p : RUNTIME_EXEC_PATTERNS) {
            if (text.contains(p)) {
                record.addSignal("BYTECODE_RUNTIME_EXEC");
                break;
            }
        }
        for (String p : SCRIPT_PATTERNS) {
            if (text.contains(p)) {
                record.addSignal("BYTECODE_SCRIPT_ENGINE");
                break;
            }
        }
    }

    /** 从 class 文件字节流中提取可打印 ASCII 串（常量池 UTF-8 项的近似提取）。 */
    public static String extractAsciiStrings(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length);
        int run = 0;
        for (byte b : bytes) {
            int v = b & 0xFF;
            if (v >= 0x20 && v < 0x7F) {
                sb.append((char) v);
                run++;
            } else {
                if (run > 0) {
                    sb.append('\n');
                }
                run = 0;
            }
        }
        return sb.toString();
    }
}
