package com.memsweep.e2e;

import com.memsweep.testkit.BenignBusinessFilter;
import com.memsweep.testkit.BusinessServlet;
import com.memsweep.testkit.MemoryClassLoader;
import org.apache.catalina.Context;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 独立运行的「受害服务器」：内嵌 Tomcat + 运行期注入的内存 Filter 马。
 * 启动后常驻，供 CLI 通过 Attach API 跨进程排查/摘除。
 */
public class VictimServer {

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(args.length > 0 ? args[0] : "18080");
        Path base = Files.createTempDirectory("memsweep-victim-");
        Tomcat tomcat = new Tomcat();
        tomcat.setBaseDir(base.toString());
        tomcat.setPort(port);
        tomcat.getConnector();
        Context context = tomcat.addContext("", base.toAbsolutePath().toString());
        StandardContext std = (StandardContext) context;

        Tomcat.addServlet(context, "business", new BusinessServlet());
        context.addServletMappingDecoded("/biz", "business");
        FilterDef benign = new FilterDef();
        benign.setFilterName("benign");
        benign.setFilter(new BenignBusinessFilter());
        std.addFilterDef(benign);
        FilterMap bm = new FilterMap();
        bm.setFilterName("benign");
        bm.addURLPattern("/*");
        std.addFilterMap(bm);

        tomcat.start();

        // 运行期注入内存马（无文件落地）
        byte[] bytes;
        try (var in = VictimServer.class.getClassLoader()
                .getResourceAsStream("com/memsweep/testkit/EvilMemoryFilter.class")) {
            bytes = in.readAllBytes();
        }
        MemoryClassLoader mem = new MemoryClassLoader(VictimServer.class.getClassLoader());
        Class<?> evilClass = mem.defineFromBytes("com.memsweep.testkit.EvilMemoryFilter", bytes);
        jakarta.servlet.Filter evil =
                (jakarta.servlet.Filter) evilClass.getDeclaredConstructor().newInstance();
        FilterDef ed = new FilterDef();
        ed.setFilterName("memsweep-evil");
        ed.setFilter(evil);
        std.addFilterDef(ed);
        FilterMap em = new FilterMap();
        em.setFilterName("memsweep-evil");
        em.addURLPattern("/*");
        std.addFilterMapBefore(em);
        Class<?> afc = Class.forName("org.apache.catalina.core.ApplicationFilterConfig");
        var ctor = afc.getDeclaredConstructor(Context.class, FilterDef.class);
        ctor.setAccessible(true);
        Object cfg = ctor.newInstance(context, ed);
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> configs =
                (java.util.Map<String, Object>) getField(std, "filterConfigs");
        configs.put("memsweep-evil", cfg);

        System.out.println("VICTIM_READY port=" + port + " pid="
                + ProcessHandle.current().pid());
        // 常驻
        Thread.currentThread().join();
    }

    private static Object getField(Object t, String name) throws Exception {
        Class<?> c = t.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(t);
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }
}
