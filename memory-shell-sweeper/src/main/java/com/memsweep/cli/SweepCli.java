package com.memsweep.cli;

import com.memsweep.agent.SweepAgent;

import java.io.BufferedReader;
import java.io.File;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 命令行入口：通过 Attach API 把 agent jar 挂载进目标 Java 进程。
 *
 * 用法：
 *   java -jar memory-shell-sweeper-agent.jar <pid> scan [--no-bytecode]
 *   java -jar memory-shell-sweeper-agent.jar <pid> dry-run
 *   java -jar memory-shell-sweeper-agent.jar <pid> remove [--ids id1,id2] [--grace-ms 5000]
 *   java -jar memory-shell-sweeper-agent.jar list
 *
 * 自身定位：从 CodeSource 反推当前 jar 路径，作为 loadAgentPath 的参数。
 * JDK 17+ Attach 同进程需要 -Djdk.attach.allowAttachSelf=true，跨进程 Attach 不需要。
 */
public final class SweepCli {

    private SweepCli() {}

    public static void main(String[] argv) throws Exception {
        List<String> args = new ArrayList<>(List.of(argv));
        if (args.isEmpty() || args.contains("-h") || args.contains("--help")) {
            printHelp();
            return;
        }
        if (args.get(0).equals("list")) {
            listJvms();
            return;
        }
        String pid = args.get(0);
        String mode = args.size() > 1 ? args.get(1) : "scan";
        String ids = optionValue(args, "--ids");
        String grace = optionValue(args, "--grace-ms");
        boolean bytecode = !args.contains("--no-bytecode");
        String dumpDir = optionValue(args, "--dump-dir");

        Path report = Files.createTempFile("memsweep-report-", ".json");
        report.toFile().deleteOnExit();

        StringBuilder agentArgs = new StringBuilder();
        agentArgs.append("mode=").append(mode);
        agentArgs.append(";bytecodeScan=").append(bytecode);
        agentArgs.append(";reportFile=").append(report.toAbsolutePath());
        if (ids != null) {
            agentArgs.append(";ids=").append(ids);
        }
        if (grace != null) {
            agentArgs.append(";graceMs=").append(grace);
        }
        if (dumpDir != null) {
            agentArgs.append(";dumpDir=").append(dumpDir);
        }

        attachAndRun(pid, agentArgs.toString(), report);
    }

    private static void attachAndRun(String pid, String agentArgs, Path report) throws Exception {
        String selfPid = ManagementFactory.getRuntimeMXBean().getName().split("@")[0];
        Path agentJar = locateAgentJar();

        if (pid.equals(selfPid)) {
            // 同进程场景：直接执行引擎，避免 Attach Self 限制
            System.err.println("[cli] attaching to self, running in-process");
            System.setProperty("jdk.attach.allowAttachSelf", "true");
        }

        Class<?> vmClass = Class.forName("com.sun.tools.attach.VirtualMachine");
        Object vm = vmClass.getMethod("attach", String.class).invoke(null, pid);
        try {
            // jar 型 agent 用 loadAgent；loadAgentPath 仅用于 .so/.dylib 本地 agent 库
            vmClass.getMethod("loadAgent", String.class, String.class)
                    .invoke(vm, agentJar.toAbsolutePath().toString(), agentArgs);
        } finally {
            vmClass.getMethod("detach").invoke(vm);
        }

        // Agent 在目标进程内把报告写入共享临时文件，等待落盘
        long deadline = System.currentTimeMillis() + 30_000;
            while (!Files.exists(report) || Files.size(report) == 0) {
                if (System.currentTimeMillis() > deadline) {
                    throw new IllegalStateException("等待目标进程输出报告超时");
                }
                Thread.sleep(100);
            }
            try (BufferedReader r = Files.newBufferedReader(report)) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = r.readLine()) != null) {
                    sb.append(line);
                }
                System.out.println(prettyPrint(sb.toString()));
            }
    }

    private static Path locateAgentJar() {
        try {
            File loc = new File(SweepAgent.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI());
            return loc.toPath();
        } catch (Exception e) {
            throw new IllegalStateException("无法定位 agent jar，请用 -jar 方式运行", e);
        }
    }

    private static void listJvms() throws Exception {
        Class<?> vmClass = Class.forName("com.sun.tools.attach.VirtualMachine");
        Object descs = vmClass.getMethod("list").invoke(null);
        java.util.List<?> list = (java.util.List<?>) descs;
        for (Object d : list) {
            String id = (String) d.getClass().getMethod("id").invoke(d);
            String display = (String) d.getClass().getMethod("displayName").invoke(d);
            System.out.printf("%8s  %s%n", id, display);
        }
    }

    private static String optionValue(List<String> args, String key) {
        int i = args.indexOf(key);
        if (i < 0 || i + 1 >= args.size()) {
            return null;
        }
        return args.get(i + 1);
    }

    /** 轻量缩进美化，保持零依赖。 */
    static String prettyPrint(String json) {
        StringBuilder sb = new StringBuilder(json.length() + 256);
        int indent = 0;
        boolean inString = false;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"') {
                int slashes = 0;
                for (int j = i - 1; j >= 0 && json.charAt(j) == '\\'; j--) {
                    slashes++;
                }
                if (slashes % 2 == 0) {
                    inString = !inString;
                }
                sb.append(c);
            } else if (!inString && (c == '{' || c == '[')) {
                sb.append(c).append('\n');
                indent++;
                sb.append("  ".repeat(indent));
            } else if (!inString && (c == '}' || c == ']')) {
                sb.append('\n');
                indent--;
                sb.append("  ".repeat(indent)).append(c);
            } else if (!inString && c == ',') {
                sb.append(c).append('\n').append("  ".repeat(indent));
            } else if (!inString && c == ':') {
                sb.append(": ");
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static void printHelp() {
        System.out.println("""
                memory-shell-sweeper - 内存驻留请求组件排查/摘除工具

                用法:
                  java -jar memory-shell-sweeper-agent.jar list
                      列出本机所有 Java 进程
                  java -jar memory-shell-sweeper-agent.jar <pid> scan [--no-bytecode]
                      只读枚举并定级（默认，不修改目标进程）
                  java -jar memory-shell-sweeper-agent.jar <pid> dry-run
                      完整走摘除流程但不修改注册表
                  java -jar memory-shell-sweeper-agent.jar <pid> remove [--ids a,b] [--grace-ms 5000]
                      摘除 MALICIOUS 组件（不带 --ids 时自动模式，仅摘高置信度目标）
                  java -jar memory-shell-sweeper-agent.jar <pid> remove --ids tomcat-3-1f2a
                      两步确认模式：先 scan 看报告，再按报告 id 精确摘除

                选项:
                  --no-bytecode   跳过 retransform 字节码扫描（降低目标 JVM 短暂开销）
                  --grace-ms N    摘除后等待在途请求的宽限时间，默认 3000ms
                  --dump-dir DIR  摘除前转储组件类字节码用于取证
                """);
    }
}
