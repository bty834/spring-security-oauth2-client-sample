package org.bty.blog.security.model;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import javax.security.auth.Subject;
import java.util.Collection;
import java.util.Collections;

/**
 * @author bty
 * @date 2023/2/6
 * @since 1.8
 **/
public class BearerTokenAuthenticationToken extends AbstractAuthenticationToken {

    private final String token;

    /**
     * Create a BearerTokenAuthenticationToken using the provided parameter(s)
     * @param token - the bearer token
     */
    public BearerTokenAuthenticationToken(String token) {
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
