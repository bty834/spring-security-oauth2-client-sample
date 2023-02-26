package com.example.blog.security.handler;


import com.example.blog.util.JacksonUtil;
import com.example.blog.util.ServletUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static javax.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8_VALUE;

/**
 * @author bty
 * @date 2022/9/26
 * @since 1.8
 * 认证已完成，但是访问的接口权限不足，抛出{@link AccessDeniedException}时可能触发该handler
 * 如果未登录且持有匿名用户身份，即使抛出{@link AccessDeniedException}不会触发这个handler，参见 {@link ExceptionTranslationFilter#handleSpringSecurityException(HttpServletRequest, HttpServletResponse, FilterChain, RuntimeException)}
 **/
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {
    private static final Logger logger = LoggerFactory.getLogger(RestAccessDeniedHandler.class);

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        logger.error(accessDeniedException.getMessage());
        ServletUtil.failureResponse(response, accessDeniedException.getMessage(), HttpStatus.valueOf(SC_FORBIDDEN));
    }
}
