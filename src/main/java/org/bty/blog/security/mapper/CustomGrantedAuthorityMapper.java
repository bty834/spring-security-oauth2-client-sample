package org.bty.blog.security.mapper;

import org.springframework.context.annotation.Bean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.stream.Collectors;

/**
 * 自定义GrantedAuthoritiesMapper
 *
 * @author bty
 * @date 2023/2/5
 * @since 1.8
 **/
@Component
public class CustomGrantedAuthorityMapper implements GrantedAuthoritiesMapper {
    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream().map(grantedAuthority -> (GrantedAuthority) () -> "gitee:"+grantedAuthority.getAuthority()).collect(Collectors.toList());
    }
}
