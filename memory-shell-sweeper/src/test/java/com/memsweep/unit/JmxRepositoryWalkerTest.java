package com.memsweep.unit;

import com.memsweep.discovery.JmxRepositoryWalker;
import org.junit.jupiter.api.Test;

import javax.management.ObjectName;
import java.lang.management.ManagementFactory;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 验证反射遍历平台 MBeanServer 内部 repository 的能力——
 * 标准 JMX API 不暴露资源实例，本工具依赖该路径发现容器组件。
 */
class JmxRepositoryWalkerTest {

    public interface ProbeMBean {
        String getLabel();
    }

    /** Standard MBean：类名 Probe + 同名接口 ProbeMBean。 */
    public static final class Probe implements ProbeMBean {
        final String label;
        Probe(String label) { this.label = label; }
        @Override public String getLabel() { return label; }
    }

    @Test
    void walksIntoPlatformMBeanServerRepository() throws Exception {
        Probe resource = new Probe("probe-target");
        ObjectName name = new ObjectName("com.memsweep.test:type=Probe,name=walk");
        ManagementFactory.getPlatformMBeanServer().registerMBean(resource, name);
        try {
            List<Object> all = JmxRepositoryWalker.allManagedResources();
            assertTrue(all.stream().anyMatch(o -> o instanceof Probe p && "probe-target".equals(p.label)),
                    "必须能从 MBeanServer 内部结构取回注册的资源实例，实际数量=" + all.size());
        } finally {
            ManagementFactory.getPlatformMBeanServer().unregisterMBean(name);
        }
    }

    @Test
    void filterBySimpleClassName_works() throws Exception {
        Probe resource = new Probe("filtered");
        ObjectName name = new ObjectName("com.memsweep.test:type=Probe,name=filter");
        ManagementFactory.getPlatformMBeanServer().registerMBean(resource, name);
        try {
            List<Object> hits = JmxRepositoryWalker.filterBySimpleClassName("Probe");
            assertTrue(hits.stream().anyMatch(o -> o == resource));
        } finally {
            ManagementFactory.getPlatformMBeanServer().unregisterMBean(name);
        }
    }
}
