package com.memsweep.testkit;

import com.memsweep.agent.SweepAgent;

import java.io.File;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 测试用自挂载辅助：通过真实 Attach API 把构建出的 agent jar 挂进当前测试 JVM，
 * 与应急响应中跨进程 loadAgentPath 的代码路径一致（仅 pid 换成自身）。
 * 需要 -Djdk.attach.allowAttachSelf=true（已在 build.gradle 的 test jvmArgs 配置）。
 */
public final class AgentAttachHelper {

    private AgentAttachHelper() {}

    private static InstrumentationHolder holder;

    /** 触发一次自挂载并返回 Instrumentation（进程内单例，重复调用返回缓存）。 */
    public static Object instrumentation() throws Exception {
        if (SweepAgent.instrumentation != null) {
            return SweepAgent.instrumentation;
        }
        if (holder == null) {
            holder = new InstrumentationHolder();
        }
        return holder.inst;
    }

    private static final class InstrumentationHolder {
        final Object inst;

        InstrumentationHolder() throws Exception {
            String pid = ManagementFactory.getRuntimeMXBean().getName().split("@")[0];
            Path agentJar = locateAgentJar();
            Class<?> vmClass = Class.forName("com.sun.tools.attach.VirtualMachine");
            Object vm = vmClass.getMethod("attach", String.class).invoke(null, pid);
            try {
                // jar 型 agent 必须用 loadAgent（loadAgentPath 用于 .so/.dylib 本地库）
                vmClass.getMethod("loadAgent", String.class, String.class)
                        .invoke(vm, agentJar.toAbsolutePath().toString(), "mode=scan");
            } finally {
                vmClass.getMethod("detach").invoke(vm);
            }
            // agentmain 在 AttachListener 线程同步执行，loadAgentPath 返回即已完成
            long deadline = System.currentTimeMillis() + 10_000;
            while (SweepAgent.instrumentation == null && System.currentTimeMillis() < deadline) {
                Thread.sleep(50);
            }
            if (SweepAgent.instrumentation == null) {
                throw new IllegalStateException("agent 自挂载后未取得 Instrumentation");
            }
            this.inst = SweepAgent.instrumentation;
        }
    }

    /** 从测试 classpath 反推 build/libs 下的 agent jar。 */
    static Path locateAgentJar() throws Exception {
        File codeSource = new File(AgentAttachHelper.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI());
        Path classesDir = codeSource.toPath(); // build/classes/java/test
        Path buildDir = classesDir;
        for (int i = 0; i < 4 && buildDir != null; i++) {
            if (buildDir.getFileName() != null && buildDir.getFileName().toString().equals("build")) {
                break;
            }
            buildDir = buildDir.getParent();
        }
        if (buildDir == null) {
            throw new IllegalStateException("无法定位 build 目录: " + codeSource);
        }
        Path libs = buildDir.resolve("libs");
        if (!Files.isDirectory(libs)) {
            throw new IllegalStateException("libs 目录不存在，请先执行 agentJar 任务: " + libs);
        }
        try (var stream = Files.list(libs)) {
            return stream.filter(p -> p.getFileName().toString().startsWith("memory-shell-sweeper-agent")
                            && p.toString().endsWith(".jar"))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("libs 下找不到 agent jar: " + libs));
        }
    }

    /** 供不需要真实 Instrumentation 的单元测试使用的空实例检查。 */
    public static boolean agentLoaded() {
        return SweepAgent.instrumentation != null;
    }

    @SuppressWarnings("unused")
    private static Method noop() { return null; }
}
