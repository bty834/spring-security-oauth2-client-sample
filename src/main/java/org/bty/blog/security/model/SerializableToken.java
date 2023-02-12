package org.bty.blog.security.model;

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.io.Serializable;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author bty
 * @date 2023/2/12
 * @since 1.8
 **/
public class SerializableToken implements Serializable {

    public enum LOGIN_TYPE {
        USERNAME, OAUTH2, OIDC
    }

    private LOGIN_TYPE loginType;

    private String username;

    private String registrationId;
    private Map<String, Object> attributes;

    private List<String> authorities;


    public SerializableToken() {
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }


    public LOGIN_TYPE getLoginType() {
        return loginType;
    }

    public void setLoginType(LOGIN_TYPE loginType) {
        this.loginType = loginType;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getRegistrationId() {
        return registrationId;
    }

    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }

    public List<String> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<String> authorities) {
        this.authorities = authorities;
    }

    public static SerializableToken adaptAuthentication(Authentication authentication) {
        SerializableToken serializableToken = null;
        List<String> authorityList = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());

        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
            serializableToken = new SerializableToken();
            serializableToken.setLoginType(LOGIN_TYPE.USERNAME);
            serializableToken.setUsername(token.getName());
            serializableToken.setAuthorities(authorityList);
        }
        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
            serializableToken = new SerializableToken();
            serializableToken.setLoginType(LOGIN_TYPE.OAUTH2);
            serializableToken.setUsername(token.getName());
            serializableToken.setAuthorities(authorityList);
            serializableToken.setRegistrationId(token.getAuthorizedClientRegistrationId());

            DefaultOAuth2User user = (DefaultOAuth2User) token.getPrincipal();
            serializableToken.setAttributes(user.getAttributes());

        }
        return serializableToken;
    }


    public static Authentication reverseAuthentication(SerializableToken st, OAuth2ClientProperties clientProperties) {
        Set<SimpleGrantedAuthority> authoritySet = st.getAuthorities().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
        if (st.getLoginType().equals(LOGIN_TYPE.USERNAME)) {
            return new UsernamePasswordAuthenticationToken(st.getUsername(), null, authoritySet);
        }
        if (st.getLoginType().equals(LOGIN_TYPE.OAUTH2)) {
            return new OAuth2AuthenticationToken(new DefaultOAuth2User(authoritySet, st.getAttributes(),
                    clientProperties.getProvider().get(st.getRegistrationId()).getUserNameAttribute()), authoritySet, st.getRegistrationId());
        }
        return null;

    }
}
