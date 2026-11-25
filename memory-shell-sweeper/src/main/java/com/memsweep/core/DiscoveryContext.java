package com.memsweep.core;

import com.memsweep.model.ComponentRecord;

import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 一次排查任务的共享上下文：持有 Instrumentation、各分析器以及适配器发现的活动对象引用。
 * 活动对象（StandardContext/FilterDef 等）只保存在内存映射里，不进入 JSON 报告，
 * 摘除阶段按 record id 取回。
 */
public class DiscoveryContext {

    private final Instrumentation instrumentation;
    private final ClassIntrospector introspector;
    private final Classifier classifier;
    private final BytecodeProbe bytecodeProbe;
    private final SweepOptions options;
    private final List<ComponentRecord> records = new ArrayList<>();
    /** record id -> 适配器私有摘除句柄（活动对象引用） */
    private final Map<String, Object> removalHandles = new HashMap<>();
    /** 去重键：容器:组件类型:组件名 */
    private final Map<String, String> dedup = new HashMap<>();

    public DiscoveryContext(Instrumentation instrumentation, SweepOptions options) {
        this.instrumentation = instrumentation;
        this.options = options;
        long start = RuntimeMXBeanAccess.startTime();
        this.introspector = new ClassIntrospector(instrumentation, start,
                ClassIntrospector.DEFAULT_ALLOW_PATTERNS);
        this.classifier = new Classifier(introspector);
        this.bytecodeProbe = new BytecodeProbe(instrumentation);
    }

    public Instrumentation getInstrumentation() { return instrumentation; }
    public ClassIntrospector getIntrospector() { return introspector; }
    public Classifier getClassifier() { return classifier; }
    public BytecodeProbe getBytecodeProbe() { return bytecodeProbe; }
    public SweepOptions getOptions() { return options; }
    public List<ComponentRecord> getRecords() { return records; }

    /** 去重注册；返回 true 表示是新组件。
     *  跨适配器按 类型+组件名 去重：专用容器适配器（先运行）的记录与摘除句柄优先，
     *  通用 Servlet API 兜底适配器产生的同组件重复项被丢弃，避免 CLASS_UNRESOLVABLE 噪声。 */
    public boolean registerIfNew(ComponentRecord record, Object removalHandle) {
        String key = record.getKind() + ":" + record.getComponentName();
        if (dedup.containsKey(key)) {
            return false;
        }
        dedup.put(key, record.getId());
        records.add(record);
        if (removalHandle != null) {
            removalHandles.put(record.getId(), removalHandle);
        }
        return true;
    }

    public Object getRemovalHandle(String id) {
        return removalHandles.get(id);
    }

    public ComponentRecord findById(String id) {
        for (ComponentRecord r : records) {
            if (r.getId().equals(id)) {
                return r;
            }
        }
        return null;
    }

    /**
     * 生成跨扫描稳定的组件 id：适配器名 + 类型 + 组件名 的短哈希。
     * 保证「先 scan 看报告、后 remove 按 id 摘除」的两步流程中，
     * 两次独立引擎运行对同一组件产生相同 id。
     */
    public String stableId(String adapter, ComponentRecord.Kind kind, String componentName) {
        String raw = adapter + "|" + kind.name() + "|" + componentName;
        return adapter + "-" + Integer.toHexString(raw.hashCode());
    }

    /** 对一个新发现的组件执行完整分析流水线：来源取证 -> 可选字节码扫描 -> 评分定级。 */
    public void analyze(ComponentRecord record, Class<?> componentClass) {
        introspector.inspect(record, componentClass);
        if (options.isBytecodeScan() && componentClass != null
                && instrumentation.isModifiableClass(componentClass)) {
            bytecodeProbe.probe(record, componentClass);
        }
        classifier.classify(record);
    }
}
