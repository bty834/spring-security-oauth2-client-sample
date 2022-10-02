package org.bty.blog.security;

import lombok.RequiredArgsConstructor;
import org.bty.blog.entity.BlogUser;
import org.bty.blog.service.PermissionService;
import org.bty.blog.service.UserService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

/**
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

        BlogUser user = userService.getUserByUsername(username);

        String[] permissions = permissionService.getPermissionsByUserId(user.getId());

        Set<GrantedAuthority> authoritySet = new HashSet<>();
        for (String permission : permissions) {
            authoritySet.add(new SimpleGrantedAuthority(permission));
        }

        return new BlogUserDetails(user,authoritySet);
    }
}
