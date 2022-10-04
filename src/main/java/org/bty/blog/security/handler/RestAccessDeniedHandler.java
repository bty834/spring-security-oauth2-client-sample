package org.bty.blog.security.handler;


import org.bty.blog.util.JacksonUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static javax.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8_VALUE;

/**
 * @author bty
 * @date 2022/9/26
 * @since 1.8
 * 认证已完成，但是访问的接口权限不足，触发该handler
 **/
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        response.setContentType(APPLICATION_JSON_UTF8_VALUE);
        response.getWriter().write(JacksonUtil.getObjectMapper().writeValueAsString(ResponseEntity.status(SC_FORBIDDEN).body(accessDeniedException.getMessage())));
    }
}
