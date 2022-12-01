package org.bty.blog.service.Impl;

import lombok.RequiredArgsConstructor;
import org.bty.blog.entity.BlogRole;
import org.bty.blog.entity.BlogUser;
import org.bty.blog.security.handler.LoginSuccessHandler;
import org.bty.blog.security.util.JwtUtil;
import org.bty.blog.service.RoleService;
import org.bty.blog.service.TokenService;
import org.bty.blog.service.UserRoleService;
import org.bty.blog.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.springframework.aop.interceptor.AsyncExecutionAspectSupport.DEFAULT_TASK_EXECUTOR_BEAN_NAME;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {
    private static final Logger logger = LoggerFactory.getLogger(TokenServiceImpl.class);



    @Value("${token.expire-minutes}")
    private Integer expireMinutes;

    private final JwtUtil jwtUtil;
    private final RedisTemplate redisTemplate;
    private final UserService userService;
    private final UserRoleService userRoleService;
    private final RoleService roleService;

    private String getTokenRedisKey(String uuid) {
        return "LOGIN" + ":" + uuid;
    }

    @Override
    public String initToken(Object user) {

        String uuid = UUID.randomUUID().toString();
        redisTemplate.opsForValue().set(getTokenRedisKey(uuid), user, expireMinutes, TimeUnit.MINUTES);
        return jwtUtil.encodeUUID(uuid);
    }

    @Override
    public Object verifyToken(String jwt) {
        String uuid = jwtUtil.decodeUUID(jwt);
        return redisTemplate.opsForValue().get(getTokenRedisKey(uuid));
    }


    @Async(DEFAULT_TASK_EXECUTOR_BEAN_NAME)
    public void completeUserInfo(OAuth2AuthenticationToken token, OAuth2User oAuth2User) {
        logger.info("async complete user info for oauth2user {}",oAuth2User);
        // 为每个第三方平台登录的创建一个角色，如ROLE_GITEE
        String roleName = "ROLE_" + token.getAuthorizedClientRegistrationId().toUpperCase();
        BlogRole role = roleService.getRoleByName(roleName);
        if (role == null) {
            Collection<? extends GrantedAuthority> authorities = oAuth2User.getAuthorities();
            role = roleService.addRole(roleName, authorities.stream().map(GrantedAuthority::getAuthority).toArray(String[]::new));
            logger.info("add new role {}",role);
        }

        String username = oAuth2User.getName();
        // 没有用户创建用户
        BlogUser user = userService.getUserByUsername(username);
        if (user == null) {
            logger.info("add new oauth2user {}",oAuth2User);
            user = userService.addUser(username, null);
        }

        // 加入用户角色对应关系
        logger.info("add user {} for role {}",oAuth2User,role);
        userRoleService.addRolesForUser(user.getId(), role.getId());
    }

}
