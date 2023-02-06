package org.bty.blog.service.Impl;

import com.auth0.jwt.interfaces.Claim;
import lombok.RequiredArgsConstructor;
import org.bty.blog.entity.BlogRole;
import org.bty.blog.entity.BlogUser;

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
import java.util.HashMap;
import java.util.Map;
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
public class RedisTokenServiceImpl implements TokenService {
    private static final Logger logger = LoggerFactory.getLogger(RedisTokenServiceImpl.class);



    @Value("${token.access-token-expire-minutes}")
    private Integer accessTokenExpireMinutes;

    @Value("${token.refresh-token-expire-minutes}")
    private Integer refreshTokenExpireMinutes;

    @Value("${token.secret}")
    private String secret;

    private final RedisTemplate redisTemplate;
    private final UserService userService;
    private final UserRoleService userRoleService;
    private final RoleService roleService;

    private String getAccessTokenRedisKey(String uuid) {
        return "ACCESS_TOKEN" + ":" + uuid;
    }
    private String getRefreshTokenRedisKey(String uuid) {
        return "REFRESH_TOKEN" + ":" + uuid;
    }
    @Override
    public String createAccessToken(Object user) {
        String accessToken = UUID.randomUUID().toString();
        redisTemplate.opsForValue().set(getAccessTokenRedisKey(accessToken), user, accessTokenExpireMinutes, TimeUnit.MINUTES);
        HashMap<String, Object> payload = new HashMap<>();
        payload.put("accessToken",accessToken);
        return JwtUtil.encode(payload,accessTokenExpireMinutes,secret);
    }

    @Override
    public String createRefreshToken(Object user) {
        String refreshToken = UUID.randomUUID().toString();
        redisTemplate.opsForValue().set(getRefreshTokenRedisKey(refreshToken), user, refreshTokenExpireMinutes, TimeUnit.MINUTES);
        HashMap<String, Object> payload = new HashMap<>();
        payload.put("refreshToken",refreshToken);
        return JwtUtil.encode(payload,accessTokenExpireMinutes,secret);
    }

    @Override
    public String refreshAccessToken(String jwt) {
        Map<String, Claim> payload = JwtUtil.decode(jwt,secret);
        String refreshToken = payload.get("refreshToken").asString();
        Object user = redisTemplate.opsForValue().getAndExpire(getAccessTokenRedisKey(refreshToken), refreshTokenExpireMinutes, TimeUnit.MINUTES);
        return createAccessToken(user);
    }


    @Override
    public Object verifyAccessToken(String jwt) {
        Map<String, Claim> payload = JwtUtil.decode(jwt,secret);
        return redisTemplate.opsForValue().get(getAccessTokenRedisKey(payload.get("accessToken").asString()));
    }




}
