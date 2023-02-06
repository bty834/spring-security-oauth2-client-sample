package org.bty.blog.service.Impl;

import lombok.RequiredArgsConstructor;
import org.bty.blog.entity.BlogRole;
import org.bty.blog.entity.BlogUser;
import org.bty.blog.service.RoleService;
import org.bty.blog.service.UserRoleService;
import org.bty.blog.service.UserService;
import org.omg.CORBA.PRIVATE_MEMBER;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collection;

import static org.springframework.aop.interceptor.AsyncExecutionAspectSupport.DEFAULT_TASK_EXECUTOR_BEAN_NAME;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final RoleService roleService;
    private final UserRoleService userRoleService;

    @Override
    public BlogUser getUserByUsername(String username) {

        String encode = new BCryptPasswordEncoder().encode("123456");
        if(username.equals("bty"))
            return new BlogUser(1,"bty",encode);
        return new BlogUser(0, "nobody", "");
    }

    @Override
    public BlogUser addUser(String username, String password) {
        // TODO: add user in database
        return new BlogUser();
    }

    @Async(DEFAULT_TASK_EXECUTOR_BEAN_NAME)
    @Override
    public void addUser(OAuth2AuthenticationToken token, OAuth2User oAuth2User) {

        // 为每个第三方平台登录的创建一个角色，如ROLE_GITEE
        String roleName = "ROLE_" + token.getAuthorizedClientRegistrationId().toUpperCase();
        BlogRole role = roleService.getRoleByName(roleName);
        if (role == null) {
            Collection<? extends GrantedAuthority> authorities = oAuth2User.getAuthorities();
            role = roleService.addRole(roleName, authorities.stream().map(GrantedAuthority::getAuthority).toArray(String[]::new));
        }

        String username = oAuth2User.getName();
        // 没有用户创建用户
        BlogUser user = getUserByUsername(username);
        if (user == null) {
            user = addUser(username, null);
        }
        // 加入用户角色对应关系
        userRoleService.addRolesForUser(user.getId(), role.getId());
    }

}
