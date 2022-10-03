package org.bty.blog.security.converter;

import lombok.RequiredArgsConstructor;
import org.bty.blog.service.TokenService;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * @author bty
 * @date 2022/10/3
 * @since 1.8
 **/
@Component
@RequiredArgsConstructor
public class BearAuthenticationConverter implements AuthenticationConverter {

    public static final String AUTHENTICATION_SCHEME_BEAR = "Bear";


    private Charset credentialsCharset = StandardCharsets.UTF_8;

    private final TokenService tokenService;

    public Charset getCredentialsCharset() {
        return this.credentialsCharset;
    }

    public void setCredentialsCharset(Charset credentialsCharset) {
        this.credentialsCharset = credentialsCharset;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null) {
            return null;
        }
        header = header.trim();
        if (!StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BEAR)) {
            return null;
        }
        if (header.equalsIgnoreCase(AUTHENTICATION_SCHEME_BEAR)) {
            throw new BadCredentialsException("Empty basic authentication token");
        }
        String jwt = header.substring(5);

        return (Authentication)tokenService.verifyToken(jwt);


    }
}
