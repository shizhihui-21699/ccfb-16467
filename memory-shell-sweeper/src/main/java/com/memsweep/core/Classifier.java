package com.memsweep.core;

import com.memsweep.model.ComponentRecord;

import java.util.List;

/**
 * 可疑度评分与定级。
 *
 * 设计原则：
 *  - 正常探针/框架动态类通过白名单和良性命名兜底，避免误伤
 *  - 单一信号只产生 SUSPICIOUS，需要多信号叠加或字节码命中才定 MALICIOUS
 *  - 摘除动作要求 MALICIOUS 且命中至少一个强信号，防止误删业务组件
 */
public class Classifier {

    /** 强信号：命中任意一个即高度可疑。类无法解析单独不算强信号（可能只是尚未实例化）。 */
    private static final List<String> STRONG_SIGNALS = List.of(
            "NULL_CODESOURCE",
            "HIDDEN_CLASS",
            "SUSPICIOUS_CLASSLOADER",
            "NON_DISK_CODESOURCE"
    );

    private final ClassIntrospector introspector;

    public Classifier(ClassIntrospector introspector) {
        this.introspector = introspector;
    }

    public ComponentRecord.Verdict classify(ComponentRecord r) {
        int score = 0;
        boolean strong = false;
        boolean allowlisted = introspector.isAllowlisted(r.getClassName());

        for (String s : r.getSignals()) {
            switch (s) {
                case "NULL_CODESOURCE" -> { score += 40; strong = true; }
                case "NON_DISK_CODESOURCE" -> { score += 35; strong = true; }
                case "IN_MEMORY_CLASS_BYTES" -> score += 25;
                case "HIDDEN_CLASS" -> { score += 40; strong = true; }
                case "JDK_DYNAMIC_PROXY", "GENERATED_CLASS_NAME" -> score += 10;
                case "SUSPICIOUS_CLASSLOADER" -> { score += 30; strong = true; }
                case "LOADED_AFTER_STARTUP" -> score += 20;
                case "RUNTIME_REGISTERED" -> score += 20;
                case "BROAD_URL_MAPPING" -> score += 10;
                case "BYTECODE_CMD_API" -> score += 45;
                case "BYTECODE_SCRIPT_ENGINE" -> score += 40;
                case "BYTECODE_RUNTIME_EXEC" -> score += 35;
                case "CLASS_UNRESOLVABLE" -> score += 10;
                default -> {
                    if (s.startsWith("NON_DISK")) { score += 30; }
                }
            }
        }

        // 白名单类大幅降权，但不直接清零（白名单类被仿冒时仍可发现）
        if (allowlisted) {
            score = score / 4;
            r.addSignal("ALLOWLIST_HIT");
        }

        r.setScore(score);
        ComponentRecord.Verdict v;
        if (score >= 60 || (strong && score >= 40) || r.getSignals().contains("BYTECODE_CMD_API")) {
            v = ComponentRecord.Verdict.MALICIOUS;
        } else if (score >= 25 || (r.isInMemoryClass() && r.isLoadedAfterStartup())) {
            v = ComponentRecord.Verdict.SUSPICIOUS;
        } else if (r.isInMemoryClass() || r.isDynamicProxy() || r.getSignals().contains("GENERATED_CLASS_NAME")) {
            v = ComponentRecord.Verdict.DYNAMIC_BENIGN;
        } else {
            v = ComponentRecord.Verdict.NORMAL;
        }
        r.setVerdict(v);
        return v;
    }

    /** 是否满足自动摘除门槛：MALICIOUS 且至少一个强信号或字节码命中。 */
    public boolean removable(ComponentRecord r) {
        if (r.getVerdict() != ComponentRecord.Verdict.MALICIOUS) {
            return false;
        }
        if (r.getSignals().contains("BYTECODE_CMD_API")
                || r.getSignals().contains("BYTECODE_RUNTIME_EXEC")
                || r.getSignals().contains("BYTECODE_SCRIPT_ENGINE")) {
            return true;
        }
        for (String s : STRONG_SIGNALS) {
            if (r.getSignals().contains(s)) {
                return true;
            }
        }
        return false;
    }
}
