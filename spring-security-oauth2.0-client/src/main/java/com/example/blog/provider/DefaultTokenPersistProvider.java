package com.example.blog.provider;

import com.example.blog.security.model.SerializableToken;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * @author bty
 * @date 2023/2/10
 * @since 1.8
 **/
@Component
@RequiredArgsConstructor
public class DefaultTokenPersistProvider implements TokenPersistProvider {

    private final RedisTemplate redisTemplate;


    @Override
    public void persist(String token, SerializableToken authentication, Integer expires, TimeUnit timeUnit) throws RuntimeException {
        try {
            redisTemplate.opsForValue().set(token, authentication, expires, timeUnit);
        } catch (Exception e) {
            throw new SessionAuthenticationException("redis set token not working");
        }
    }

    @Override
    public SerializableToken get(String token, Integer expires, TimeUnit timeUnit) throws RuntimeException {
        SerializableToken o;
        try {
            o = (SerializableToken)redisTemplate.opsForValue().get(token);
        } catch (RuntimeException e) {
            throw new SessionAuthenticationException("token expired, pls login in");
        }

        if(o!=null){
            persist(token, o, expires, timeUnit);
            return o;
        }
        throw new SessionAuthenticationException("token expired, pls login in");
    }

    @Override
    public void invalid(String token) throws RuntimeException {
        try {
            redisTemplate.delete(token);
        } catch (Exception e) {
            throw new RuntimeException("token delete error");
        }
    }
}
