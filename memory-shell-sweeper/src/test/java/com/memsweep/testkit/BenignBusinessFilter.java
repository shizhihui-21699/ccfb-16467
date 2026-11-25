package com.memsweep.testkit;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/** 正常业务 Filter：磁盘类加载，codeSource 指向测试 classpath，用于验证不会误伤。 */
public class BenignBusinessFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        ((HttpServletResponse) response).setHeader("X-Benign", "ok");
        chain.doFilter(request, response);
    }
}
