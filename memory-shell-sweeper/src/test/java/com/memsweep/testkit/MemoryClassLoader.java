package com.memsweep.testkit;

import java.util.HashMap;
import java.util.Map;

/**
 * 模拟攻击者的内存类加载器：只通过 defineClass(byte[]) 定义类，
 * 类字节码不来自任何 jar/目录，ProtectionDomain 的 CodeSource 为 null。
 * 这是反序列化内存马最典型的载体形态。
 */
public class MemoryClassLoader extends ClassLoader {

    private final Map<String, byte[]> classBytes = new HashMap<>();

    public MemoryClassLoader(ClassLoader parent) {
        super("memsweep-memory-loader", parent);
    }

    public Class<?> defineFromBytes(String name, byte[] bytes) {
        classBytes.put(name, bytes);
        // 单参/双参 defineClass 不提供 ProtectionDomain，CodeSource 为 null
        return defineClass(name, bytes, 0, bytes.length);
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        byte[] bytes = classBytes.get(name);
        if (bytes == null) {
            throw new ClassNotFoundException(name);
        }
        return defineClass(name, bytes, 0, bytes.length);
    }

    public byte[] storedBytes(String name) {
        return classBytes.get(name);
    }
}
