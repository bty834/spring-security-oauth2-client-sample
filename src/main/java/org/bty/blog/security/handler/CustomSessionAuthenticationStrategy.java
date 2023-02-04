package org.bty.blog.security.handler;

import lombok.RequiredArgsConstructor;
import org.bty.blog.security.model.RedisOAuth2User;
import org.bty.blog.security.model.RedisUserDetail;
import org.bty.blog.service.TokenService;
import org.bty.blog.util.JacksonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
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
@RequiredArgsConstructor
public class CustomSessionAuthenticationStrategy implements SessionAuthenticationStrategy {
    private static final Logger logger = LoggerFactory.getLogger(CustomSessionAuthenticationStrategy.class);

    private final TokenService tokenService;

    /**
     *
     * NOT recommended <br/>
     * Cause if do this below,
     * {@link SecurityContextHolder} won't hold {@link SecurityContext} with authenticated {@link Authentication},
     * and {@link AuthenticationSuccessHandler}s won't work
     *
     * about the word flow , see {@link AbstractAuthenticationProcessingFilter#doFilter(HttpServletRequest, HttpServletResponse, FilterChain)}
     * @param authentication
     * @param request
     * @param response
     * @throws SessionAuthenticationException
     */
    @Override
    public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response) throws SessionAuthenticationException {
        logger.info("CustomSessionAuthenticationStrategy called");

        // sessionStuff

        // *********************************
        // below is NOT NOT NOT recommended
        // *********************************
        //
        //        response.setContentType(APPLICATION_JSON_UTF8_VALUE);
        //        try {
        //            response.getWriter().write(
        //                    JacksonUtil.getObjectMapper().writeValueAsString(
        //                            ResponseEntity.ok(Collections.singletonMap("token", "be careful"))
        //                    )
        //            );
        //        } catch (IOException e) {
        //            throw new RuntimeException(e);
        //        }

    }
}
