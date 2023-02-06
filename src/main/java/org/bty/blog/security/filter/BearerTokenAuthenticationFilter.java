package org.bty.blog.security.filter;

import lombok.RequiredArgsConstructor;
import org.bty.blog.security.BearerTokenAuthenticationManager;
import org.bty.blog.security.converter.BearerTokenResolver;
import org.bty.blog.security.entrypoint.RestAuthenticationEntrypoint;
import org.bty.blog.security.handler.RestFailureHandler;
import org.bty.blog.security.model.BearerTokenAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author bty
 * @date 2023/2/6
 * @since 1.8
 **/
@Component
@RequiredArgsConstructor
public class BearerTokenAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(BearerTokenAuthenticationFilter.class);

    private final RestAuthenticationEntrypoint entrypoint;

    private final BearerTokenResolver bearerTokenResolver;

    private final BearerTokenAuthenticationManager authenticationManager;

    private final RestFailureHandler failureHandler;

    private SecurityContextRepository securityContextRepository = new NullSecurityContextRepository();

    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();



    public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;
    }

    public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if(request.getServletPath().startsWith("/login") || request.getServletPath().startsWith("/oauth2")){
            logger.info("skip token authentication for path {}",request.getServletPath());
            filterChain.doFilter(request,response);
            return;
        }

        String token;

        try {
            token = this.bearerTokenResolver.resolve(request);
        }
        catch (OAuth2AuthenticationException invalid) {
            logger.trace("Sending to authentication entry point since failed to resolve bearer token", invalid);
            this.entrypoint.commence(request, response, invalid);
            return;
        }
        if(token == null){
            logger.info("bearer token is null");
            filterChain.doFilter(request,response);
            return;
        }

        BearerTokenAuthenticationToken bearerTokenAuthenticationToken = new BearerTokenAuthenticationToken(token);
        bearerTokenAuthenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));

        try {
            Authentication authenticationResult = authenticationManager.authenticate(bearerTokenAuthenticationToken);
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authenticationResult);
            SecurityContextHolder.setContext(context);
            this.securityContextRepository.saveContext(context, request, response);
            logger.info("SecurityContext Authentication:{}",authenticationResult);
            filterChain.doFilter(request,response);
        } catch (AuthenticationException e) {
            SecurityContextHolder.clearContext();
            this.failureHandler.onAuthenticationFailure(request, response, e);
        }

    }
}
