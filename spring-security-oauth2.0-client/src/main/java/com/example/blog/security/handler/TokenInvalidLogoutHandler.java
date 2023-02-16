package com.example.blog.security.handler;

import com.example.blog.security.converter.BearerTokenResolver;
import com.example.blog.service.TokenService;
import com.google.common.base.Strings;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author bty
 * @date 2023/2/12
 * @since 1.8
 **/
@Component
@RequiredArgsConstructor
public class TokenInvalidLogoutHandler implements LogoutHandler {
    private static final Logger logger = LoggerFactory.getLogger(TokenInvalidLogoutHandler.class);

    private final BearerTokenResolver bearerTokenResolver;
    private final TokenService tokenService;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String token = bearerTokenResolver.resolve(request);
        if(Strings.isNullOrEmpty(token)){
            return;
        }
        tokenService.invalidToken(token);
    }

}
