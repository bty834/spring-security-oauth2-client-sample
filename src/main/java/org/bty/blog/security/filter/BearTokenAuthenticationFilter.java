package org.bty.blog.security.filter;

import lombok.RequiredArgsConstructor;
import org.bty.blog.security.converter.BearTokenAuthenticationConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author bty
 * @date 2022/10/3
 * @since 1.8
 **/
@Component
@RequiredArgsConstructor
public class BearTokenAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(BearTokenAuthenticationFilter.class);

    private final AuthenticationEntryPoint authenticationEntryPoint;

    private final BearTokenAuthenticationConverter bearTokenAuthenticationConverter;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if(request.getServletPath().startsWith("/login") || request.getServletPath().startsWith("/oauth2")){
            logger.info("skip token authentication for path {}",request.getServletPath());
            filterChain.doFilter(request,response);
            return;
        }

        try {
            Authentication authentication = this.bearTokenAuthenticationConverter.convert(request);
            if(authentication==null){
                filterChain.doFilter(request,response);
                return;
            }
            logger.info("bearer token authenticated successfully");
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (AuthenticationException ex) {
            logger.error("bearer token authenticated failed for {}",ex.getMessage());
            SecurityContextHolder.clearContext();
            this.authenticationEntryPoint.commence(request, response, ex);
        }
        filterChain.doFilter(request,response);

    }
}
