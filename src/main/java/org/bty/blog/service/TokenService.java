package org.bty.blog.service;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
public interface TokenService {

    String initToken(Object info);

    Object verifyToken(String jwt);
}
