package com.memsweep.adapters;

import com.memsweep.core.ContainerAdapter;
import com.memsweep.core.DiscoveryContext;
import com.memsweep.discovery.JmxRepositoryWalker;
import com.memsweep.discovery.LoadedClassDetector;
import com.memsweep.model.ComponentRecord;
import com.memsweep.util.Reflect;

import java.util.List;

/**
 * Undertow 适配器（只读）。
 *
 * Undertow 的 Servlet 注册信息保存在 DeploymentInfo 快照里，运行期部署后的
 * 管理 API（DeploymentManagerImpl）没有公共的单点摘除方法，强行反射改写内部
 * path matching 结构容易让在途请求 NPE。因此策略为：
 *   - 能枚举则完整枚举并定级
 *   - 摘除返回 NOT_SUPPORTED，报告中给出人工处置建议（重建 DeploymentInfo 热重载）
 */
public class UndertowAdapter implements ContainerAdapter {

    public static final String NAME = "undertow";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public boolean isPresent(DiscoveryContext ctx) {
        return LoadedClassDetector.anyLoaded(ctx.getInstrumentation(),
                "io.undertow.servlet.core.DeploymentImpl",
                "io.undertow.Undertow");
    }

    @Override
    public void discover(DiscoveryContext ctx) {
        // DeploymentImpl -> deploymentInfo (DeploymentInfo) -> filters / servletInfos
        for (Object deployment : JmxRepositoryWalker.filterBySimpleClassName("DeploymentImpl")) {
            Object info = Reflect.getField(deployment, "deploymentInfo");
            if (info == null) {
                info = Reflect.invoke(deployment, "getDeploymentInfo");
            }
            if (info == null) {
                continue;
            }
            inspectFilters(ctx, info);
            inspectServlets(ctx, info);
        }
    }

    private void inspectFilters(DiscoveryContext ctx, Object deploymentInfo) {
        Object filters = Reflect.invoke(deploymentInfo, "getFilters");
        if (!(filters instanceof List<?> list)) {
            return;
        }
        for (Object filterInfo : list) {
            String name = (String) Reflect.invoke(filterInfo, "getName");
            Object filterClass = Reflect.getField(filterInfo, "filterClass");
            Class<?> clazz = filterClass instanceof Class<?> c ? c
                    : forName((String) Reflect.invoke(filterInfo, "getFilterClass"));
            ComponentRecord r = new ComponentRecord(nextId(ctx, ComponentRecord.Kind.FILTER, name));
            r.setKind(ComponentRecord.Kind.FILTER);
            r.setComponentName(name);
            r.setDiscoveredBy(NAME);
            ctx.analyze(r, clazz);
            ctx.registerIfNew(r, null);
        }
    }

    private void inspectServlets(DiscoveryContext ctx, Object deploymentInfo) {
        Object servlets = Reflect.invoke(deploymentInfo, "getServlets");
        if (!(servlets instanceof List<?> list)) {
            return;
        }
        for (Object servletInfo : list) {
            String name = (String) Reflect.invoke(servletInfo, "getName");
            Class<?> clazz = forName((String) Reflect.invoke(servletInfo, "getServletClass"));
            ComponentRecord r = new ComponentRecord(nextId(ctx, ComponentRecord.Kind.SERVLET, name));
            r.setKind(ComponentRecord.Kind.SERVLET);
            r.setComponentName(name);
            r.setDiscoveredBy(NAME);
            ctx.analyze(r, clazz);
            ctx.registerIfNew(r, null);
        }
    }

    private Class<?> forName(String name) {
        if (name == null) {
            return null;
        }
        try {
            return Class.forName(name, false, Thread.currentThread().getContextClassLoader());
        } catch (Throwable t) {
            return null;
        }
    }

    @Override
    public RemovalOutcome remove(DiscoveryContext ctx, String recordId) {
        return RemovalOutcome.unsupported(
                "Undertow 不支持运行期单点摘除；建议在 DeploymentInfo 中移除对应组件后通过 "
                        + "DeploymentManagerImpl.undeploy()/deploy() 热重载，避免破坏在途请求");
    }

    private String nextId(DiscoveryContext ctx, ComponentRecord.Kind kind, String name) {
        return ctx.stableId(NAME, kind, name);
    }
}
