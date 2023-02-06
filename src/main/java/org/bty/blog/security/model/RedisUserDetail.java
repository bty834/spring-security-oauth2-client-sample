package org.bty.blog.security.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 用于存储到Redis的登录信息实体，适用于UsernamePassword Login
 * @author bty
 * @date 2022/10/4
 * @since 1.8
 **/
public class RedisUserDetail implements UserDetails,Serializable {
    private String username;

    private List<String> permissions;

    public RedisUserDetail() {
    }

    public RedisUserDetail(UserDetails userDetails) {
        this.username = userDetails.getUsername();
        Collection<? extends GrantedAuthority> collection = userDetails.getAuthorities();
        this.permissions = collection.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
    }

    @JsonIgnore
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return permissions.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
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

    @JsonIgnore
    @Override
    public String getPassword() {
        return null;
    }

    public String getUsername() {
        return username;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isEnabled() {
        return true;
    }


}
