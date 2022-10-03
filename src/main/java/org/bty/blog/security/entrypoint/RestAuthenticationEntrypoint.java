package org.bty.blog.security.entrypoint;

import org.bty.blog.util.JacksonUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

import static javax.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8_VALUE;

/**
 * @author bty
 * @date 2022/10/3
 * @since 1.8
 **/
@Component
public class RestAuthenticationEntrypoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setContentType(APPLICATION_JSON_UTF8_VALUE);
        response.getWriter().write(JacksonUtil.getObjectMapper().writeValueAsString(ResponseEntity.status(SC_FORBIDDEN).body(Collections.singletonMap("msg", authException.getMessage()))));
    }
}
