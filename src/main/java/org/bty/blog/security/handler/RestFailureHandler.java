package org.bty.blog.security.handler;

import org.bty.blog.util.JacksonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8_VALUE;

/**
 * @author bty
 * @date 2023/2/4
 * @since 1.8
 **/
@Component
public class RestFailureHandler implements AuthenticationFailureHandler {
    private static final Logger logger = LoggerFactory.getLogger(RestFailureHandler.class);

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        logger.error(exception.getMessage());
        response.setContentType(APPLICATION_JSON_UTF8_VALUE);
        response.getWriter().write(
                JacksonUtil.getObjectMapper().writeValueAsString(
                        ResponseEntity.status(HttpStatus.EXPECTATION_FAILED).body(Collections.singletonMap("msg", exception.getMessage())))
        );
    }
}
