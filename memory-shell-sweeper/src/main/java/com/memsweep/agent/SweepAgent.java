package com.memsweep.agent;

import com.memsweep.core.SweepEngine;

import java.io.PrintWriter;
import java.lang.instrument.Instrumentation;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * JVM Agent 入口。
 *
 * 支持三种挂载方式：
 *   1. 启动期：-javaagent:sweeper.jar=mode=scan
 *   2. 运行期 Attach：VirtualMachine.loadAgentPath(jar, args) —— 应急响应主场景
 *   3. 自挂载：Launcher-Agent-Class（同进程工具化场景）
 *
 * 输出方式：
 *   - args 含 reportFile=/path 时把 JSON 报告写入文件（跨进程 Attach 唯一可靠回传方式）
 *   - 同时在目标进程 stdout 打印一行带标记的报告路径，便于 CLI 捕获
 */
public class SweepAgent {

    public static final String REPORT_MARKER = "MEMSweep-report:";

    /** Agent 挂载后保存的 Instrumentation 实例，供同进程工具化/测试使用。 */
    public static volatile Instrumentation instrumentation;

    public static void premain(String agentArgs, Instrumentation inst) {
        instrumentation = inst;
        run(agentArgs, inst);
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        instrumentation = inst;
        run(agentArgs, inst);
    }

    private static void run(String agentArgs, Instrumentation inst) {
        String reportFile = extractArg(agentArgs, "reportFile");
        try {
            String json = SweepEngine.runAsJson(inst, agentArgs);
            if (reportFile != null) {
                Path p = Paths.get(reportFile);
                Files.createDirectories(p.toAbsolutePath().getParent());
                try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(p, StandardCharsets.UTF_8))) {
                    w.print(json);
                }
                System.out.println(REPORT_MARKER + p.toAbsolutePath());
            } else {
                System.out.println(REPORT_MARKER + "inline");
                System.out.println(json);
            }
        } catch (Throwable t) {
            System.err.println("[memory-shell-sweeper] fatal: " + t);
            t.printStackTrace(System.err);
        }
    }

    private static String extractArg(String args, String key) {
        if (args == null) {
            return null;
        }
        for (String pair : args.split(";")) {
            int eq = pair.indexOf('=');
            if (eq > 0 && pair.substring(0, eq).trim().equals(key)) {
                return pair.substring(eq + 1).trim();
            }
        }
        return null;
    }
}
