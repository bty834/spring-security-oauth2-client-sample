package org.bty.blog.security.converter;

import lombok.RequiredArgsConstructor;

import org.bty.blog.security.model.RedisOAuth2User;
import org.bty.blog.security.model.RedisUserDetail;
import org.bty.blog.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;


/**
 * @author bty
 * @date 2022/10/3
 * @since 1.8
 **/
@Component
@RequiredArgsConstructor
public class BearTokenAuthenticationConverter implements AuthenticationConverter {
    private static final Logger logger = LoggerFactory.getLogger(BearTokenAuthenticationConverter.class);

    public static final String AUTHENTICATION_SCHEME_BEAR = "Bearer";
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
            logger.info("header is null");
            return null;
        }
        header = header.trim();
        if (!StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BEAR)) {
            logger.warn("header Authentication is not bearer token");
            return null;
        }
        if (header.equalsIgnoreCase(AUTHENTICATION_SCHEME_BEAR)) {
            logger.error("Empty basic authentication token");
            throw new BadCredentialsException("Empty basic authentication token");
        }
        String jwt = header.substring(7);
        Authentication authentication = null;

        Object o = tokenService.verifyToken(jwt);

        if (o instanceof RedisUserDetail) {

            RedisUserDetail userDetail = (RedisUserDetail) o;
            authentication = new UsernamePasswordAuthenticationToken(userDetail.getUsername(),
                    null,
                    userDetail.getAuthorities());

        } else if (o instanceof RedisOAuth2User) {
            RedisOAuth2User oAuth2User = (RedisOAuth2User) o;
            authentication = new OAuth2AuthenticationToken(oAuth2User, oAuth2User.getAuthorities(), oAuth2User.getRegistrationId());
        }
        logger.info("bearer token is authenticated , authentication is :{}",authentication);
        return authentication;
    }
}
