package org.bty.blog.provider;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * @author bty
 * @date 2023/2/10
 * @since 1.8
 **/
@Component
@RequiredArgsConstructor
public class DefaultTokenPersistProvider implements TokenPersistProvider{

    private final RedisTemplate redisTemplate;

    @Override
    public void persist(String token, Object user, Integer expires, TimeUnit timeUnit) {
        redisTemplate.opsForValue().set(token, user, expires, timeUnit);
    }

    @Override
    public Object get(String token, Integer expires, TimeUnit timeUnit) {
        return redisTemplate.opsForValue().getAndExpire(token, expires, timeUnit);
    }
}
