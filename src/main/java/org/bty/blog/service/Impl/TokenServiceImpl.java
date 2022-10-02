package org.bty.blog.service.Impl;

import lombok.RequiredArgsConstructor;
import org.bty.blog.security.util.JwtUtil;
import org.bty.blog.service.TokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    @Value("${token.expire-minutes}")
    private Integer expireMinutes;

    private final JwtUtil jwtUtil;
    private final RedisTemplate redisTemplate;

    private String getTokenRedisKey(String uuid) {


        return "LOGIN" + ":" + uuid;
    }

    @Override
    public String initToken(Object value) {

        String uuid = UUID.randomUUID().toString();

        redisTemplate.opsForValue().set(getTokenRedisKey(uuid), value, expireMinutes, TimeUnit.MINUTES);

        return jwtUtil.encodeUUID(uuid);
    }

    @Override
    public Object verifyToken(String jwt) {
        String uuid = jwtUtil.decodeUUID(jwt);
        return redisTemplate.opsForValue().get(getTokenRedisKey(uuid));
    }
}
