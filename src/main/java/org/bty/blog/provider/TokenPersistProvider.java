package org.bty.blog.provider;

import org.bty.blog.security.model.SerializableToken;

import java.nio.file.AccessDeniedException;
import java.util.concurrent.TimeUnit;

/**
 * @author bty
 * @date 2023/2/10
 * @since 1.8
 **/
public interface TokenPersistProvider<T extends SerializableToken> {

    void persist(String token,  T authentication, Integer expires, TimeUnit timeUnit) throws RuntimeException;


    T get(String token, Integer expires, TimeUnit timeUnit) throws RuntimeException;

    void invalid(String token) throws RuntimeException;
}
