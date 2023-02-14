package org.bty.blog.security.service;

import lombok.RequiredArgsConstructor;
import org.bty.blog.entity.BlogUser;
import org.bty.blog.service.Impl.UserServiceImpl;
import org.bty.blog.service.PermissionService;
import org.bty.blog.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * UsernamePassword Login 流程中的 {@link DaoAuthenticationProvider}最终调用该接口实现类<br/>
 * 用户修改密码请调用 {@link UserDetailsManager}接口，不要去实现 {@link UserDetailsPasswordService} <br/>
 * {@link UserDetailsPasswordService} 在 {@link DaoAuthenticationProvider} 中是每次登录成功都 update password。<br/>
 * 主动修改密码建议使用{@link UserDetailsManager}，该类继承自{@link UserDetailsService}
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
@Component
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsManager,UserDetailsService {

    public static final Logger LOGGER = LoggerFactory.getLogger(CustomUserDetailsService.class);

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

    /**
     * 请自己实现api或通过filter实现
     * @param user
     */
    @Override
    public void createUser(UserDetails user) {
        userService.addUser(user.getUsername(), user.getPassword());
    }

    /**
     * 请自己实现api或通过filter实现
     * @param user
     */
    @Override
    public void updateUser(UserDetails user) {
        Assert.isTrue(userExists(user.getUsername()), "user should exist");
        LOGGER.info("ur updating user");
    }

    /**
     * 请自己实现api或通过filter实现
     * @param
     */
    @Override
    public void deleteUser(String username) {
        Assert.isTrue(userExists(username), "user should exist");
        LOGGER.info("ur deleting user");
    }

    /**
     * 请自己实现api或通过filter实现
     * @param
     */
    @Override
    public void changePassword(String oldPassword, String newPassword) {
        LOGGER.info("ur changing pwd");
    }

    /**
     * 请自己实现api或通过filter实现
     * @param
     */
    @Override
    public boolean userExists(String username) {
        return true;
    }
}
