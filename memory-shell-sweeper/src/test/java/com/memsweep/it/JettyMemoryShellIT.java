package com.memsweep.it;

import com.memsweep.core.SweepEngine;
import com.memsweep.core.SweepEngine.SweepResult;
import com.memsweep.core.SweepOptions;
import com.memsweep.model.ComponentRecord;
import com.memsweep.testkit.AgentAttachHelper;
import com.memsweep.testkit.BenignBusinessFilter;
import com.memsweep.testkit.BusinessServlet;
import com.memsweep.testkit.EvilMemoryFilter;
import com.memsweep.testkit.MemoryClassLoader;
import org.eclipse.jetty.jmx.MBeanContainer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.FilterMapping;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.lang.instrument.Instrumentation;
import java.lang.management.ManagementFactory;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import jakarta.servlet.DispatcherType;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 端到端：内嵌 Jetty 11（jakarta）+ 运行期内存 Filter 马。
 *
 * 开启 MBeanContainer，验证 JMX 路径发现；摘除走 ServletHandler 公共数组重建 API，
 * 验证 chain cache 失效后内存马请求 404、业务请求不中断。
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class JettyMemoryShellIT {

    private Server server;
    private ServletContextHandler context;
    private ServletHandler servletHandler;
    private int port;
    private Instrumentation inst;
    private HttpClient http;
    private final String evilFilterName = "memsweep-evil-jetty";
    private String evilRecordId;

    @BeforeAll
    void startContainer() throws Exception {
        inst = (Instrumentation) AgentAttachHelper.instrumentation();

        server = new Server(0);
        MBeanContainer mbeans = new MBeanContainer(ManagementFactory.getPlatformMBeanServer());
        server.addBean(mbeans);

        context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        server.setHandler(context);
        servletHandler = context.getServletHandler();

        context.addServlet(new ServletHolder("business", new BusinessServlet()), "/biz");
        FilterHolder benign = new FilterHolder(new BenignBusinessFilter());
        benign.setName("benign");
        context.addFilter(benign, "/*", EnumSet.of(DispatcherType.REQUEST));

        server.start();
        port = ((ServerConnector) server.getConnectors()[0]).getLocalPort();
        http = HttpClient.newHttpClient();
        assertTrue(port > 0);

        // —— 模拟攻击：运行期内存定义并插入恶意 Filter ——
        byte[] evilBytes;
        try (var in = EvilMemoryFilter.class.getClassLoader()
                .getResourceAsStream(EvilMemoryFilter.class.getName().replace('.', '/') + ".class")) {
            assertNotNull(in);
            evilBytes = in.readAllBytes();
        }
        MemoryClassLoader memLoader = new MemoryClassLoader(getClass().getClassLoader());
        Class<?> evilClass = memLoader.defineFromBytes(
                "com.memsweep.testkit.EvilMemoryFilter", evilBytes);
        jakarta.servlet.Filter evilFilter =
                (jakarta.servlet.Filter) evilClass.getDeclaredConstructor().newInstance();

        FilterHolder evilHolder = new FilterHolder();
        evilHolder.setName(evilFilterName);
        evilHolder.setFilter(evilFilter);
        FilterMapping evilMapping = new FilterMapping();
        evilMapping.setFilterName(evilFilterName);
        evilMapping.setPathSpecs(new String[]{"/*"});
        evilMapping.setDispatches(FilterMapping.REQUEST);

        // 运行期插入 holder/mapping 到链首
        FilterHolder[] holders = append(servletHandler.getFilters(), evilHolder, FilterHolder.class);
        FilterMapping[] mappings = prepend(servletHandler.getFilterMappings(), evilMapping, FilterMapping.class);
        servletHandler.setFilters(holders);
        servletHandler.setFilterMappings(mappings);
        invokeUpdateMappings(servletHandler);

        HttpResponse<String> warm = get("/biz");
        assertEquals("present", warm.headers().firstValue("X-Evil-Filter").orElse(null));
        assertEquals(200, warm.statusCode());
    }

    @AfterAll
    void stopContainer() throws Exception {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    @Order(1)
    void scan_discoversViaJmxAndClassifies() {
        SweepResult result = new SweepEngine(inst, options(SweepOptions.Mode.SCAN)).runWithContext();

        ComponentRecord evil = byName(result, evilFilterName);
        assertNotNull(evil, "必须通过 JMX/线程根枚举到 Jetty 恶意 Filter，适配器错误="
                + result.report().get("adapterErrors"));
        evilRecordId = evil.getId();
        assertEquals(ComponentRecord.Verdict.MALICIOUS, evil.getVerdict(),
                "内存 Filter 马应判定 MALICIOUS，信号=" + evil.getSignals());
        assertTrue(evil.isInMemoryClass());
        assertTrue(evil.getSignals().stream().anyMatch(s -> s.startsWith("BYTECODE_HIT")));

        ComponentRecord benign = byName(result, "benign");
        assertNotNull(benign);
        assertEquals(ComponentRecord.Verdict.NORMAL, benign.getVerdict(),
                "磁盘 Filter 不得误伤，信号=" + benign.getSignals());
    }

    @Test
    @Order(2)
    void remove_evictsAndBusinessSurvives() {
        SweepOptions opts = options(SweepOptions.Mode.REMOVE);
        opts.setTargetIds(List.of(evilRecordId));
        SweepResult result = new SweepEngine(inst, opts).runWithContext();

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> removals = (List<Map<String, Object>>) result.report().get("removals");
        assertEquals("REMOVED", removals.get(0).get("status"), "摘除结果: " + removals.get(0));

        HttpResponse<String> after = get("/biz");
        assertTrue(after.headers().firstValue("X-Evil-Filter").isEmpty());
        assertEquals(200, after.statusCode());
        assertEquals("business-ok", after.body());
        assertEquals("ok", after.headers().firstValue("X-Benign").orElse(null));
    }

    @Test
    @Order(3)
    void rescan_confirmsEviction() {
        SweepResult result = new SweepEngine(inst, options(SweepOptions.Mode.SCAN)).runWithContext();
        assertTrue(result.context().getRecords().stream()
                .noneMatch(r -> evilFilterName.equals(r.getComponentName())));
    }

    private ComponentRecord byName(SweepResult result, String name) {
        return result.context().getRecords().stream()
                .filter(r -> name.equals(r.getComponentName()))
                .findFirst().orElse(null);
    }

    private SweepOptions options(SweepOptions.Mode mode) {
        SweepOptions o = new SweepOptions();
        o.setMode(mode);
        o.setBytecodeScan(true);
        o.setGracePeriodMs(300);
        return o;
    }

    private HttpResponse<String> get(String path) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                    .GET().timeout(java.time.Duration.ofSeconds(5)).build();
            return http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void invokeUpdateMappings(ServletHandler handler) throws Exception {
        var m = ServletHandler.class.getDeclaredMethod("updateMappings");
        m.setAccessible(true);
        m.invoke(handler);
    }

    @SuppressWarnings("unchecked")
    private <T> T[] append(T[] arr, T item, Class<T> type) {
        int n = arr == null ? 0 : arr.length;
        T[] out = (T[]) java.lang.reflect.Array.newInstance(type, n + 1);
        if (arr != null) {
            System.arraycopy(arr, 0, out, 0, n);
        }
        out[n] = item;
        return out;
    }

    @SuppressWarnings("unchecked")
    private <T> T[] prepend(T[] arr, T item, Class<T> type) {
        int n = arr == null ? 0 : arr.length;
        T[] out = (T[]) java.lang.reflect.Array.newInstance(type, n + 1);
        out[0] = item;
        if (arr != null) {
            System.arraycopy(arr, 0, out, 1, n);
        }
        return out;
    }
}
