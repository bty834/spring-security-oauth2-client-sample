package org.bty.blog.security;

import lombok.RequiredArgsConstructor;
import org.bty.blog.security.model.JwtAuthenticationToken;
import org.bty.blog.security.model.SerializableToken;
import org.bty.blog.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Component;

/**
 * 用于BearerToken的认证，具体由{@link TokenService}实现
 *
 * @author bty
 * @date 2023/2/6
 * @since 1.8
 **/
@Component
@RequiredArgsConstructor
public class JwtAuthenticationManager implements AuthenticationManager {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationManager.class);

    private final TokenService tokenService;

    private final OAuth2ClientProperties p;

    /**
     * @param authentication {@link JwtAuthenticationToken}
     * @return {@link UsernamePasswordAuthenticationToken} or {@link OAuth2AuthenticationToken}
     * @throws AuthenticationException
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;

        String token = jwtToken.getToken();

        try {
            SerializableToken o = tokenService.verifyAccessToken(token);

            Authentication reverseAuthentication = SerializableToken.reverseAuthentication(o, p);

            if (reverseAuthentication == null) {
                throw new SessionAuthenticationException("session not found");
            }
            logger.info("bearer token is authenticated , authentication is :{}", authentication);
            return reverseAuthentication;
        } catch (RuntimeException e) {
            throw new SessionAuthenticationException(e.getMessage());
        }
    }
}
