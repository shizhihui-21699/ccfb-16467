package com.memsweep.adapters;

import com.memsweep.core.ContainerAdapter;
import com.memsweep.core.DiscoveryContext;
import com.memsweep.discovery.JmxRepositoryWalker;
import com.memsweep.discovery.LoadedClassDetector;
import com.memsweep.discovery.ThreadRootWalker;
import com.memsweep.model.ComponentRecord;
import com.memsweep.util.Reflect;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * WebLogic 适配器（只读）。
 *
 * WebLogic 的 Filter/Servlet 注册在 weblogic.servlet.internal.WebAppServletContext
 * 内部，其内部结构跨大版本（12c/14c）差异大且没有稳定公共摘除 API，
 * 反射摘除有破坏 weblogic 工作管理器在途请求的风险，因此：
 *   - 通过 JMX ComponentMBean / 线程根找到 WebAppServletContext
 *   - 复用其 getFilterRegistrations()/getServletRegistrations()（Servlet 标准 API）做枚举
 *   - 摘除标记 NOT_SUPPORTED，输出控制台 WLST 热重启建议
 */
public class WebLogicAdapter implements ContainerAdapter {

    public static final String NAME = "weblogic";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public boolean isPresent(DiscoveryContext ctx) {
        return LoadedClassDetector.anyLoaded(ctx.getInstrumentation(),
                "weblogic.servlet.internal.WebAppServletContext",
                "weblogic.t3.srvr.ServerRuntime");
    }

    @Override
    public void discover(DiscoveryContext ctx) {
        Set<Integer> seen = new LinkedHashSet<>();
        List<Object> contexts = new ArrayList<>();
        for (Object o : JmxRepositoryWalker.filterBySimpleClassName("WebAppServletContext")) {
            if (seen.add(System.identityHashCode(o))) {
                contexts.add(o);
            }
        }
        for (Object o : ThreadRootWalker.findBySimpleClassName("WebAppServletContext")) {
            if (seen.add(System.identityHashCode(o))) {
                contexts.add(o);
            }
        }
        for (Object ctxObj : contexts) {
            Object servletContext = Reflect.invoke(ctxObj, "getServletContext");
            if (servletContext != null) {
                new ServletApiAdapter().discover(ctx);
            }
        }
    }

    @Override
    public RemovalOutcome remove(DiscoveryContext ctx, String recordId) {
        return RemovalOutcome.unsupported(
                "WebLogic 内部注册表跨版本不稳定，不做反射摘除；建议通过 WLST 更新部署描述符后 "
                        + "执行应用级 redeploy（会话可保留），或在流量网关封禁对应 URL");
    }
}
