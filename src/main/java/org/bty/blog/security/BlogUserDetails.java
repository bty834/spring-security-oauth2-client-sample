package org.bty.blog.security;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.bty.blog.entity.BlogUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
public class BlogUserDetails extends BlogUser implements UserDetails {

    Collection<? extends GrantedAuthority> authorities;

    public BlogUserDetails(BlogUser blogUser, Collection<? extends GrantedAuthority> authorities) {
        super(blogUser.getId(), blogUser.getUsername(), blogUser.getPassword());
        this.authorities = authorities;
    }

    @JsonIgnore
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @JsonIgnore
    @Override
    public String getPassword() {
        return super.getPassword();
    }
    @Override
    public String getUsername() {
        return super.getUsername();
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
