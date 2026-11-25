package com.memsweep.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 单个请求处理组件（Filter / Servlet / Handler / Listener / Mapping）的枚举记录。
 * 纯数据对象，可序列化为 JSON 报告。
 */
public class ComponentRecord {

    public enum Kind {
        FILTER, SERVLET, LISTENER, SPRING_HANDLER, JERSEY_RESOURCE, UNKNOWN
    }

    public enum Verdict {
        /** 高置信度恶意，建议摘除 */
        MALICIOUS,
        /** 存在多个可疑信号，需人工确认 */
        SUSPICIOUS,
        /** 动态生成但无明显恶意特征（监控探针/框架增强类常见） */
        DYNAMIC_BENIGN,
        /** 磁盘可加载的常规组件 */
        NORMAL,
        /** 信息不足 */
        UNKNOWN
    }

    /** 摘除动作的执行结果 */
    public enum RemoveStatus {
        REMOVED, DRY_RUN, FAILED, NOT_SUPPORTED, DESTROY_FAILED
    }

    private final String id;
    private Kind kind = Kind.UNKNOWN;
    private String componentName;
    /** URL 映射，如 /*、/api/shell */
    private List<String> urlMappings = new ArrayList<>();
    private String className;
    /** 类加载器的描述信息（不持有强引用，仅保留文本） */
    private String classLoaderInfo;
    private String codeSource;
    private boolean inMemoryClass;
    private boolean hiddenClass;
    private boolean dynamicProxy;
    private boolean bootstrapLoaded;
    private long classLoadTimestamp;
    private long jvmStartTime;
    private boolean loadedAfterStartup;
    private List<String> signals = new ArrayList<>();
    private int score;
    private Verdict verdict = Verdict.UNKNOWN;
    /** 发现来源：tomcat/jetty/undertow/weblogic/spring/servlet-api/jmx 等 */
    private String discoveredBy;
    /** 摘除结果，仅 remove 模式下填充 */
    private RemoveStatus removeStatus;
    private String removeMessage;

    public ComponentRecord(String id) {
        this.id = id;
    }

    public String getId() { return id; }
    public Kind getKind() { return kind; }
    public void setKind(Kind kind) { this.kind = kind; }
    public String getComponentName() { return componentName; }
    public void setComponentName(String componentName) { this.componentName = componentName; }
    public List<String> getUrlMappings() { return urlMappings; }
    public void setUrlMappings(List<String> urlMappings) { this.urlMappings = urlMappings; }
    public String getClassName() { return className; }
    public void setClassName(String className) { this.className = className; }
    public String getClassLoaderInfo() { return classLoaderInfo; }
    public void setClassLoaderInfo(String classLoaderInfo) { this.classLoaderInfo = classLoaderInfo; }
    public String getCodeSource() { return codeSource; }
    public void setCodeSource(String codeSource) { this.codeSource = codeSource; }
    public boolean isInMemoryClass() { return inMemoryClass; }
    public void setInMemoryClass(boolean inMemoryClass) { this.inMemoryClass = inMemoryClass; }
    public boolean isHiddenClass() { return hiddenClass; }
    public void setHiddenClass(boolean hiddenClass) { this.hiddenClass = hiddenClass; }
    public boolean isDynamicProxy() { return dynamicProxy; }
    public void setDynamicProxy(boolean dynamicProxy) { this.dynamicProxy = dynamicProxy; }
    public boolean isBootstrapLoaded() { return bootstrapLoaded; }
    public void setBootstrapLoaded(boolean bootstrapLoaded) { this.bootstrapLoaded = bootstrapLoaded; }
    public long getClassLoadTimestamp() { return classLoadTimestamp; }
    public void setClassLoadTimestamp(long classLoadTimestamp) { this.classLoadTimestamp = classLoadTimestamp; }
    public long getJvmStartTime() { return jvmStartTime; }
    public void setJvmStartTime(long jvmStartTime) { this.jvmStartTime = jvmStartTime; }
    public boolean isLoadedAfterStartup() { return loadedAfterStartup; }
    public void setLoadedAfterStartup(boolean loadedAfterStartup) { this.loadedAfterStartup = loadedAfterStartup; }
    public List<String> getSignals() { return signals; }
    public void addSignal(String signal) { this.signals.add(signal); }
    public int getScore() { return score; }
    public void setScore(int score) { this.score = score; }
    public Verdict getVerdict() { return verdict; }
    public void setVerdict(Verdict verdict) { this.verdict = verdict; }
    public String getDiscoveredBy() { return discoveredBy; }
    public void setDiscoveredBy(String discoveredBy) { this.discoveredBy = discoveredBy; }
    public RemoveStatus getRemoveStatus() { return removeStatus; }
    public void setRemoveStatus(RemoveStatus removeStatus) { this.removeStatus = removeStatus; }
    public String getRemoveMessage() { return removeMessage; }
    public void setRemoveMessage(String removeMessage) { this.removeMessage = removeMessage; }

    /** 输出为有序 Map，供 JSON 序列化使用 */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("kind", kind.name());
        m.put("componentName", componentName);
        m.put("urlMappings", urlMappings);
        m.put("className", className);
        m.put("classLoader", classLoaderInfo);
        m.put("codeSource", codeSource);
        m.put("inMemoryClass", inMemoryClass);
        m.put("hiddenClass", hiddenClass);
        m.put("dynamicProxy", dynamicProxy);
        m.put("bootstrapLoaded", bootstrapLoaded);
        m.put("classLoadTimestamp", classLoadTimestamp);
        m.put("jvmStartTime", jvmStartTime);
        m.put("loadedAfterStartup", loadedAfterStartup);
        m.put("signals", signals);
        m.put("score", score);
        m.put("verdict", verdict.name());
        m.put("discoveredBy", discoveredBy);
        if (removeStatus != null) {
            m.put("removeStatus", removeStatus.name());
            m.put("removeMessage", removeMessage);
        }
        return m;
    }
}
