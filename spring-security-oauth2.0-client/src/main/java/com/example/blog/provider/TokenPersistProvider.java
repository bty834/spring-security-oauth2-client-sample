package com.example.blog.provider;

import com.example.blog.security.model.SerializableToken;

import java.util.concurrent.TimeUnit;

/**
 * @author bty
 * @date 2023/2/10
 * @since 17
 **/
public interface TokenPersistProvider<T extends SerializableToken> {

    void persist(String token,  T authentication, Integer expires, TimeUnit timeUnit) throws RuntimeException;


    T get(String token, Integer expires, TimeUnit timeUnit) throws RuntimeException;

    void invalid(String token) throws RuntimeException;
}
