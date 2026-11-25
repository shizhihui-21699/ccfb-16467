package com.memsweep.it;

import com.memsweep.core.SweepEngine;
import com.memsweep.core.SweepOptions;
import com.memsweep.core.SweepEngine.SweepResult;
import com.memsweep.model.ComponentRecord;
import com.memsweep.testkit.AgentAttachHelper;
import com.memsweep.testkit.BenignBusinessFilter;
import com.memsweep.testkit.BusinessServlet;
import com.memsweep.testkit.EvilMemoryFilter;
import com.memsweep.testkit.MemoryClassLoader;
import org.apache.catalina.Context;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 端到端：内嵌 Tomcat 10（jakarta）+ 运行期内存 Filter 马。
 *
 * 验证：
 *   1. 扫描能枚举全部 Filter/Servlet
 *   2. 内存定义的恶意 Filter 被定 MALICIOUS，磁盘业务组件不被误伤
 *   3. dry-run 不修改注册表
 *   4. remove 后内存马 URL 失效，正常业务请求全程可用（在途安全）
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class TomcatMemoryShellIT {

    private Tomcat tomcat;
    private Context context;
    private int port;
    private Instrumentation inst;
    private HttpClient http;
    private final String evilFilterName = "memsweep-evil";
    private String evilRecordId;

    @BeforeAll
    void startContainer() throws Exception {
        inst = (Instrumentation) AgentAttachHelper.instrumentation();

        Path base = Files.createTempDirectory("memsweep-tomcat-");
        tomcat = new Tomcat();
        tomcat.setBaseDir(base.toString());
        tomcat.setPort(0);
        tomcat.getConnector();
        context = tomcat.addContext("", base.toAbsolutePath().toString());

        // 正常业务组件（磁盘类）
        Tomcat.addServlet(context, "business", new BusinessServlet());
        context.addServletMappingDecoded("/biz", "business");
        StandardContext stdContext = (StandardContext) context;
        FilterDef benignDef = new FilterDef();
        benignDef.setFilterName("benign");
        benignDef.setFilter(new BenignBusinessFilter());
        stdContext.addFilterDef(benignDef);
        FilterMap benignMap = new FilterMap();
        benignMap.setFilterName("benign");
        benignMap.addURLPattern("/*");
        stdContext.addFilterMap(benignMap);

        tomcat.start();
        port = tomcat.getConnector().getLocalPort();
        http = HttpClient.newHttpClient();

        // —— 模拟攻击：服务运行后，用内存 ClassLoader 定义恶意类并动态注册 ——
        byte[] evilBytes = classBytesOf(EvilMemoryFilter.class);
        MemoryClassLoader memLoader = new MemoryClassLoader(getClass().getClassLoader());
        Class<?> evilClass = memLoader.defineFromBytes(
                "com.memsweep.testkit.EvilMemoryFilter", evilBytes);
        jakarta.servlet.Filter evilFilter =
                (jakarta.servlet.Filter) evilClass.getDeclaredConstructor().newInstance();

        FilterDef evilDef = new FilterDef();
        evilDef.setFilterName(evilFilterName);
        evilDef.setFilter(evilFilter);
        stdContext.addFilterDef(evilDef);
        FilterMap evilMap = new FilterMap();
        evilMap.setFilterName(evilFilterName);
        evilMap.addURLPattern("/*");
        stdContext.addFilterMapBefore(evilMap); // 内存马通常插到链首

        // 真实内存马手法：运行期手动构造 ApplicationFilterConfig 并塞进 filterConfigs，
        // 否则 Tomcat 不会为运行期新增的 FilterDef 建立配置和实例
        Class<?> afcClass = Class.forName("org.apache.catalina.core.ApplicationFilterConfig");
        var ctor = afcClass.getDeclaredConstructor(Context.class, FilterDef.class);
        ctor.setAccessible(true);
        Object filterConfig = ctor.newInstance(context, evilDef);
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> filterConfigs =
                (java.util.Map<String, Object>) getField(stdContext, "filterConfigs");
        filterConfigs.put(evilFilterName, filterConfig);

        // 预热：确保请求链包含恶意 Filter
        HttpResponse<String> warm = get("/biz");
        assertEquals("present", warm.headers().firstValue("X-Evil-Filter").orElse(null));
        assertEquals("ok", warm.headers().firstValue("X-Benign").orElse(null));
        assertEquals(200, warm.statusCode());
    }

    /** 读取测试类自身字节码，交给内存 loader 重新定义（模拟无文件落地的字节码来源）。 */
    private byte[] classBytesOf(Class<?> c) throws IOException {
        String resource = c.getName().replace('.', '/') + ".class";
        try (var in = c.getClassLoader().getResourceAsStream(resource)) {
            assertNotNull(in, "测试类字节码资源应存在: " + resource);
            return in.readAllBytes();
        }
    }

    @AfterAll
    void stopContainer() throws Exception {
        if (tomcat != null) {
            tomcat.stop();
            tomcat.destroy();
        }
    }

    @Test
    @Order(1)
    void scan_discoversAndClassifiesComponents() throws Exception {
        SweepResult result = new SweepEngine(inst, options(SweepOptions.Mode.SCAN)).runWithContext();

        ComponentRecord evil = byName(result, evilFilterName);
        assertNotNull(evil, "必须枚举到恶意 Filter");
        evilRecordId = evil.getId();
        assertEquals(ComponentRecord.Verdict.MALICIOUS, evil.getVerdict(),
                "内存 Filter 马应判定 MALICIOUS，信号=" + evil.getSignals());
        assertTrue(evil.isInMemoryClass(), "应识别为内存定义类");
        assertTrue(evil.getSignals().stream().anyMatch(s -> s.startsWith("BYTECODE_HIT")),
                "字节码探针应命中命令执行 API，信号=" + evil.getSignals());
        assertTrue(evil.getClassLoaderInfo().contains("MemoryClassLoader"),
                "类加载器信息应指向内存 loader: " + evil.getClassLoaderInfo());

        ComponentRecord benign = byName(result, "benign");
        assertNotNull(benign);
        assertNotEquals(ComponentRecord.Verdict.MALICIOUS, benign.getVerdict(),
                "磁盘业务 Filter 不得误伤，信号=" + benign.getSignals());
        assertEquals(ComponentRecord.Verdict.NORMAL, benign.getVerdict());

        ComponentRecord servlet = byName(result, "business");
        assertNotNull(servlet);
        assertNotEquals(ComponentRecord.Verdict.MALICIOUS, servlet.getVerdict());
    }

    @Test
    @Order(2)
    void dryRun_doesNotModifyRegistry() {
        SweepResult result = new SweepEngine(inst, options(SweepOptions.Mode.DRY_RUN)).runWithContext();
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> removals = (List<Map<String, Object>>) result.report().get("removals");
        assertTrue(removals.stream().anyMatch(m -> String.valueOf(m.get("message")).contains("dry-run")));

        // 注册表未变，恶意 Filter 仍在链上
        HttpResponse<String> resp = get("/biz");
        assertEquals("present", resp.headers().firstValue("X-Evil-Filter").orElse(null));
    }

    @Test
    @Order(3)
    void remove_evictsMemoryShellWithoutBreakingTraffic() {
        SweepOptions opts = options(SweepOptions.Mode.REMOVE);
        opts.setTargetIds(List.of(evilRecordId));
        SweepResult result = new SweepEngine(inst, opts).runWithContext();

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> removals = (List<Map<String, Object>>) result.report().get("removals");
        assertEquals(1, removals.size());
        assertEquals("REMOVED", removals.get(0).get("status"),
                "摘除结果: " + removals.get(0));

        // 内存马已摘：恶意响应头消失
        HttpResponse<String> after = get("/biz");
        assertTrue(after.headers().firstValue("X-Evil-Filter").isEmpty(),
                "摘除后恶意 Filter 不应再处理请求");
        // 业务正常：状态 200、业务体不变、正常 Filter 仍在
        assertEquals(200, after.statusCode());
        assertEquals("business-ok", after.body());
        assertEquals("ok", after.headers().firstValue("X-Benign").orElse(null));
    }

    @Test
    @Order(4)
    void rescan_afterRemoval_showsNoMaliciousFilter() {
        SweepResult result = new SweepEngine(inst, options(SweepOptions.Mode.SCAN)).runWithContext();
        assertTrue(result.context().getRecords().stream()
                        .noneMatch(r -> evilFilterName.equals(r.getComponentName())),
                "复扫不应再出现已摘除的内存马");
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
        o.setGracePeriodMs(500);
        return o;
    }

    private static Object getField(Object target, String name) throws Exception {
        Class<?> c = target.getClass();
        while (c != null) {
            try {
                var f = c.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(target);
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
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
}
