package com.memsweep.core;

import java.lang.management.ManagementFactory;

/** RuntimeMXBean 访问隔离，便于测试替换。 */
public final class RuntimeMXBeanAccess {

    private RuntimeMXBeanAccess() {}

    public static long startTime() {
        try {
            return ManagementFactory.getRuntimeMXBean().getStartTime();
        } catch (Exception e) {
            return -1;
        }
    }
}
