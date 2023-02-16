package com.example.blog.security.entrypoint;


import com.example.blog.security.handler.RestFailureHandler;
import com.example.blog.util.ServletUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 用于 {@link ExceptionTranslationFilter#handleSpringSecurityException(HttpServletRequest, HttpServletResponse, FilterChain, RuntimeException)}
 * 当用户未登录，且以匿名方式访问受限api时的操作。
 * 默认实现 {@link DelegatingAuthenticationEntryPoint} ，其中代理了{@link LoginUrlAuthenticationEntryPoint}，会重定向到登录页面
 * 但是前后端分离时不需要重定向。只需传回json，然前端处理即可。
 * @author bty
 * @date 2022/10/3
 * @since 1.8
 **/
@Component
public class RestAuthenticationEntrypoint implements AuthenticationEntryPoint {
    private static final Logger logger = LoggerFactory.getLogger(RestFailureHandler.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

        logger.error(authException.getMessage());

        ServletUtil.failureResponse(response, authException.getMessage(), HttpStatus.FORBIDDEN);

      }
}
