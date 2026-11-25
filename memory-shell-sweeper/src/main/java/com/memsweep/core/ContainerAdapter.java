package com.memsweep.core;

/**
 * 容器/框架适配器接口。每个适配器只负责：
 *   1. 判断目标 JVM 里是否存在本类容器（按已加载类名探测，不触发类加载）
 *   2. 反射枚举其中的请求处理组件
 *   3. 对支持的容器执行安全摘除
 * 适配器之间完全独立，单个适配器抛异常不影响其它适配器。
 */
public interface ContainerAdapter {

    String name();

    /** 通过 Instrumentation 已加载类集合判断容器是否存在。 */
    boolean isPresent(DiscoveryContext ctx);

    /** 枚举组件，结果写入 ctx；异常由编排器捕获隔离。 */
    void discover(DiscoveryContext ctx) throws Exception;

    /**
     * 摘除组件。
     * @return 摘除结果消息；不支持时返回 null 并由编排器标记 NOT_SUPPORTED
     */
    RemovalOutcome remove(DiscoveryContext ctx, String recordId) throws Exception;

    record RemovalOutcome(boolean success, boolean supported, String message) {
        public static RemovalOutcome ok(String msg) { return new RemovalOutcome(true, true, msg); }
        public static RemovalOutcome unsupported(String msg) { return new RemovalOutcome(false, false, msg); }
        public static RemovalOutcome failed(String msg) { return new RemovalOutcome(false, true, msg); }
    }
}
