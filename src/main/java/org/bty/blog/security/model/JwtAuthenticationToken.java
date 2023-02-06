package org.bty.blog.security.model;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Collections;

/**
 * @author bty
 * @date 2023/2/6
 * @since 1.8
 **/
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final String token;

    /**
     * Create a BearerTokenAuthenticationToken using the provided parameter(s)
     * @param token - the bearer token
     */
    public JwtAuthenticationToken(String token) {
        super(Collections.emptyList());
        Assert.hasText(token, "token cannot be empty");
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return getToken();
    }

    @Override
    public Object getPrincipal() {
        return getToken();
    }
}
