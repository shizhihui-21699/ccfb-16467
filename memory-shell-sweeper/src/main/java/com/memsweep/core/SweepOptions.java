package com.memsweep.core;

import java.util.LinkedHashMap;
import java.util.Map;

/** 排查动作参数。 */
public class SweepOptions {

    public enum Mode {
        /** 只枚举与定级，不做任何修改 */
        SCAN,
        /** 枚举并演示摘除步骤，但不真正修改注册表 */
        DRY_RUN,
        /** 真正摘除 MALICIOUS 组件 */
        REMOVE
    }

    private Mode mode = Mode.SCAN;
    private boolean bytecodeScan = true;
    /** 指定 id 摘除（两步确认模式）；为空表示按定级自动摘除 */
    private java.util.List<String> targetIds = new java.util.ArrayList<>();
    /** 摘除后调用 destroy() 前的宽限毫秒数，等待在途请求完成 */
    private long gracePeriodMs = 3000;
    /** 摘除前把组件类字节码转储到该目录（取证），为空则不转储 */
    private String dumpDir;

    public Mode getMode() { return mode; }
    public void setMode(Mode mode) { this.mode = mode; }
    public boolean isBytecodeScan() { return bytecodeScan; }
    public void setBytecodeScan(boolean bytecodeScan) { this.bytecodeScan = bytecodeScan; }
    public java.util.List<String> getTargetIds() { return targetIds; }
    public void setTargetIds(java.util.List<String> targetIds) { this.targetIds = targetIds; }
    public long getGracePeriodMs() { return gracePeriodMs; }
    public void setGracePeriodMs(long gracePeriodMs) { this.gracePeriodMs = gracePeriodMs; }
    public String getDumpDir() { return dumpDir; }
    public void setDumpDir(String dumpDir) { this.dumpDir = dumpDir; }

    public static SweepOptions parse(String args) {
        SweepOptions o = new SweepOptions();
        if (args == null || args.isBlank()) {
            return o;
        }
        for (String pair : args.split(";")) {
            int eq = pair.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String k = pair.substring(0, eq).trim();
            String v = pair.substring(eq + 1).trim();
            switch (k) {
                case "mode" -> o.setMode(Mode.valueOf(v.toUpperCase().replace('-', '_')));
                case "bytecodeScan" -> o.setBytecodeScan(Boolean.parseBoolean(v));
                case "ids" -> o.setTargetIds(java.util.Arrays.asList(v.split(",")));
                case "graceMs" -> o.setGracePeriodMs(Long.parseLong(v));
                case "dumpDir" -> o.setDumpDir(v);
                default -> { }
            }
        }
        return o;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("mode", mode.name());
        m.put("bytecodeScan", bytecodeScan);
        m.put("targetIds", targetIds);
        m.put("gracePeriodMs", gracePeriodMs);
        m.put("dumpDir", dumpDir);
        return m;
    }
}
