package org.bty.blog.security.service;

import lombok.RequiredArgsConstructor;
import org.bty.blog.entity.BlogUser;
import org.bty.blog.service.PermissionService;
import org.bty.blog.service.UserService;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * UsernamePassword Login 流程中的 {@link DaoAuthenticationProvider}最终调用该接口实现类
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
@Component
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserService userService;
    private final PermissionService permissionService;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        BlogUser blogUser = userService.getUserByUsername(username);

        // 查用户的角色，再根据角色查权限
        String[] permissions = permissionService.getPermissionsByUserId(blogUser.getId());

        //
        List<SimpleGrantedAuthority> simpleGrantedAuthorities =
                Arrays.stream(permissions).map(SimpleGrantedAuthority::new).collect(Collectors.toList());

        return new User(blogUser.getUsername(), blogUser.getPassword(), simpleGrantedAuthorities);
    }
}
