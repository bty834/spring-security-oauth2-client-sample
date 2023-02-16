package com.example.blog.security.handler;

import com.example.blog.util.ServletUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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
        ServletUtil.failureResponse(response, exception.getMessage(), HttpStatus.EXPECTATION_FAILED);
    }
}
