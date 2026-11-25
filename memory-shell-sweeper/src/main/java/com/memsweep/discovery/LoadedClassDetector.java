package com.memsweep.discovery;

import java.lang.instrument.Instrumentation;
import java.util.HashSet;
import java.util.Set;

/** 基于 Instrumentation 已加载类集合的容器存在性探测，不触发任何类加载。 */
public final class LoadedClassDetector {

    private LoadedClassDetector() {}

    private static Set<String> loadedNames(Instrumentation inst) {
        Set<String> names = new HashSet<>(4096);
        for (Class<?> c : inst.getAllLoadedClasses()) {
            names.add(c.getName());
        }
        return names;
    }

    public static boolean anyLoaded(Instrumentation inst, String... fqcnCandidates) {
        Set<String> loaded = loadedNames(inst);
        for (String c : fqcnCandidates) {
            if (loaded.contains(c)) {
                return true;
            }
        }
        return false;
    }

    public static boolean allLoaded(Instrumentation inst, String... fqcnCandidates) {
        Set<String> loaded = loadedNames(inst);
        for (String c : fqcnCandidates) {
            if (!loaded.contains(c)) {
                return false;
            }
        }
        return true;
    }
}
