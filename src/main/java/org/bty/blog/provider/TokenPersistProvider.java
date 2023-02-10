package org.bty.blog.provider;

import java.util.concurrent.TimeUnit;

/**
 * @author bty
 * @date 2023/2/10
 * @since 1.8
 **/
public interface TokenPersistProvider {

    void persist(String token, Object user, Integer expires, TimeUnit timeUnit);


    Object get(String token, Integer expires, TimeUnit timeUnit);

}
