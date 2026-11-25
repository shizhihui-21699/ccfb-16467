package com.memsweep.unit;

import com.memsweep.core.BytecodeProbe;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** 字节码 ASCII 常量提取的纯逻辑测试。 */
class BytecodeProbeTest {

    @Test
    void extractAsciiStrings_keepsConstantPoolText() {
        byte[] classLike = ("\u0001\u0002java/lang/Runtime\u0000exec\u0003hello world")
                .getBytes(StandardCharsets.ISO_8859_1);
        String text = BytecodeProbe.extractAsciiStrings(classLike);
        assertTrue(text.contains("java/lang/Runtime"));
        assertTrue(text.contains("exec"));
        assertTrue(text.contains("hello world"));
    }

    @Test
    void extractAsciiStrings_handlesBinaryNoise() {
        byte[] noisy = new byte[256];
        for (int i = 0; i < noisy.length; i++) {
            noisy[i] = (byte) i;
        }
        String text = BytecodeProbe.extractAsciiStrings(noisy);
        assertNotNull(text);
        // 不可打印字节被切断，不会产生异常
        assertFalse(text.contains("\u0000"));
    }
}
