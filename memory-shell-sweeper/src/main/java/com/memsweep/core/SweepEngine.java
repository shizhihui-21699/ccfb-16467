package com.memsweep.core;

import com.memsweep.adapters.JettyAdapter;
import com.memsweep.adapters.ServletApiAdapter;
import com.memsweep.adapters.SpringMvcAdapter;
import com.memsweep.adapters.TomcatAdapter;
import com.memsweep.adapters.UndertowAdapter;
import com.memsweep.adapters.WebLogicAdapter;
import com.memsweep.model.ComponentRecord;
import com.memsweep.util.Json;

import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 排查编排引擎。
 *
 * 两阶段设计：
 *   阶段 1（SCAN）：所有适配器各自枚举、取证、定级，输出完整报告。任何适配器异常被隔离，
 *                  不影响其它容器的发现结果。
 *   阶段 2（REMOVE）：只对报告中的目标 id 摘除。目标来源两种：
 *                     - 显式 ids 参数（两步确认，先看报告再摘除，最安全）
 *                     - 自动模式：仅摘除 Classifier.removable() 判定通过的 MALICIOUS 组件
 *
 * 摘除安全性：
 *   - 摘除前再次复评定级，防止状态变化后误删
 *   - DRY_RUN 模式完整走流程但不修改注册表
 *   - 摘除动作通过容器自身公共方法/内部锁执行，宽限等待在途请求
 */
public class SweepEngine {

    private final Instrumentation inst;
    private final SweepOptions options;
    private final List<ContainerAdapter> adapters;
    private final List<String> adapterErrors = new ArrayList<>();

    public SweepEngine(Instrumentation inst, SweepOptions options) {
        this.inst = inst;
        this.options = options;
        this.adapters = List.of(
                new TomcatAdapter(),
                new JettyAdapter(),
                new SpringMvcAdapter(),
                new UndertowAdapter(),
                new WebLogicAdapter(),
                new ServletApiAdapter()
        );
    }

    public Map<String, Object> run() {
        return runWithContext().report();
    }

    /** 完整执行并同时返回报告与发现上下文（上下文用于按强类型记录做摘除/测试断言）。 */
    public SweepResult runWithContext() {
        DiscoveryContext ctx = new DiscoveryContext(inst, options);

        // ---------- 阶段 1：枚举 ----------
        List<String> activeAdapters = new ArrayList<>();
        for (ContainerAdapter adapter : adapters) {
            boolean present;
            try {
                present = adapter.isPresent(ctx);
            } catch (Exception e) {
                adapterErrors.add(adapter.name() + " presence check failed: " + e);
                continue;
            }
            if (!present) {
                continue;
            }
            activeAdapters.add(adapter.name());
            try {
                adapter.discover(ctx);
            } catch (Throwable t) {
                adapterErrors.add(adapter.name() + " discover failed: "
                        + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }

        Map<String, Object> report = buildReport(ctx, activeAdapters);

        // ---------- 阶段 2：摘除 ----------
        if (options.getMode() == SweepOptions.Mode.DRY_RUN
                || options.getMode() == SweepOptions.Mode.REMOVE) {
            report.put("removals", executeRemovals(ctx));
        }
        report.put("adapterErrors", adapterErrors);
        return new SweepResult(report, ctx);
    }

    /** 一次排查的完整产物：JSON 报告 + 内存中的发现上下文。 */
    public record SweepResult(Map<String, Object> report, DiscoveryContext context) {}

    private List<Map<String, Object>> executeRemovals(DiscoveryContext ctx) {
        List<Map<String, Object>> results = new ArrayList<>();
        List<ComponentRecord> targets = selectTargets(ctx);

        for (ComponentRecord r : targets) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("id", r.getId());
            item.put("componentName", r.getComponentName());
            item.put("verdict", r.getVerdict().name());

            // 摘除前复核：自动模式只摘仍满足 removable 门槛的组件
            if (options.getTargetIds().isEmpty() && !ctx.getClassifier().removable(r)) {
                item.put("status", ComponentRecord.RemoveStatus.NOT_SUPPORTED.name());
                item.put("message", "复评未达自动摘除门槛，跳过（可用显式 ids 强制指定）");
                r.setRemoveStatus(ComponentRecord.RemoveStatus.NOT_SUPPORTED);
                results.add(item);
                continue;
            }
            ContainerAdapter adapter = adapterByName(r.getDiscoveredBy());
            if (adapter == null) {
                item.put("status", ComponentRecord.RemoveStatus.NOT_SUPPORTED.name());
                item.put("message", "找不到适配器 " + r.getDiscoveredBy());
                results.add(item);
                continue;
            }
            try {
                ContainerAdapter.RemovalOutcome outcome = adapter.remove(ctx, r.getId());
                item.put("message", outcome.message());
                if (options.getMode() == SweepOptions.Mode.DRY_RUN) {
                    // dry-run 完整走流程但不改注册表，独立状态避免与真实 REMOVED 混淆
                    r.setRemoveStatus(ComponentRecord.RemoveStatus.DRY_RUN);
                    item.put("status", ComponentRecord.RemoveStatus.DRY_RUN.name());
                } else if (!outcome.supported()) {
                    r.setRemoveStatus(ComponentRecord.RemoveStatus.NOT_SUPPORTED);
                    item.put("status", ComponentRecord.RemoveStatus.NOT_SUPPORTED.name());
                } else if (outcome.success()) {
                    r.setRemoveStatus(ComponentRecord.RemoveStatus.REMOVED);
                    item.put("status", ComponentRecord.RemoveStatus.REMOVED.name());
                } else {
                    r.setRemoveStatus(ComponentRecord.RemoveStatus.FAILED);
                    item.put("status", ComponentRecord.RemoveStatus.FAILED.name());
                }
            } catch (Throwable t) {
                r.setRemoveStatus(ComponentRecord.RemoveStatus.FAILED);
                item.put("status", ComponentRecord.RemoveStatus.FAILED.name());
                item.put("message", t.getClass().getSimpleName() + ": " + t.getMessage());
            }
            results.add(item);
        }
        return results;
    }

    private List<ComponentRecord> selectTargets(DiscoveryContext ctx) {
        List<ComponentRecord> targets = new ArrayList<>();
        if (!options.getTargetIds().isEmpty()) {
            for (String id : options.getTargetIds()) {
                ComponentRecord r = ctx.findById(id.trim());
                if (r != null) {
                    targets.add(r);
                }
            }
            return targets;
        }
        // 自动模式：摘 MALICIOUS 且通过门槛的
        for (ComponentRecord r : ctx.getRecords()) {
            if (r.getVerdict() == ComponentRecord.Verdict.MALICIOUS) {
                targets.add(r);
            }
        }
        return targets;
    }

    private ContainerAdapter adapterByName(String name) {
        for (ContainerAdapter a : adapters) {
            if (a.name().equals(name)) {
                return a;
            }
        }
        return null;
    }

    private Map<String, Object> buildReport(DiscoveryContext ctx, List<String> activeAdapters) {
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("tool", "memory-shell-sweeper");
        report.put("mode", options.getMode().name());
        report.put("timestamp", System.currentTimeMillis());
        report.put("jvmStartTime", ctx.getIntrospector().getJvmStartMillis());
        report.put("activeAdapters", activeAdapters);
        report.put("options", options.toMap());

        Map<String, Integer> verdictCount = new LinkedHashMap<>();
        for (ComponentRecord.Verdict v : ComponentRecord.Verdict.values()) {
            verdictCount.put(v.name(), 0);
        }
        List<Map<String, Object>> components = new ArrayList<>();
        for (ComponentRecord r : ctx.getRecords()) {
            verdictCount.merge(r.getVerdict().name(), 1, Integer::sum);
            components.add(r.toMap());
        }
        report.put("totalComponents", components.size());
        report.put("verdictSummary", verdictCount);
        report.put("components", components);
        return report;
    }

    public static String runAsJson(Instrumentation inst, String agentArgs) {
        SweepOptions options = SweepOptions.parse(agentArgs);
        SweepEngine engine = new SweepEngine(inst, options);
        return Json.write(engine.run());
    }
}
