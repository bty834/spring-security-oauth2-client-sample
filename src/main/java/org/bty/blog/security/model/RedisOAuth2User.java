package org.bty.blog.security.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author bty
 * @date 2022/10/4
 * @since 1.8
 **/
public class RedisOAuth2User implements OAuth2User, Serializable {

    private String username;
    private List<String> permissions;
    private Map<String, Object> attributes;
    private String registrationId;

    public RedisOAuth2User() {
    }
    public RedisOAuth2User(OAuth2User user,String registrationId) {
        this.username = user.getName();
        this.attributes = user.getAttributes();
        Collection<? extends GrantedAuthority> collection = user.getAuthorities();
        this.permissions = collection.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        this.registrationId = registrationId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public List<String> getPermissions() {
        return permissions;
    }

    public void setPermissions(List<String> permissions) {
        this.permissions = permissions;
    }

    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    public String getRegistrationId() {
        return registrationId;
    }

    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @JsonIgnore
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return permissions.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    @JsonIgnore
    @Override
    public String getName() {
        return username;
    }
}
