package org.bty.blog.service;

import org.bty.blog.security.model.SerializableToken;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
public interface TokenService<T extends SerializableToken> {


    /**
     * including accessToken and refreshToken
     *
     * @param user
     * @return
     */
    String createAccessToken(T user) throws RuntimeException;

    String createRefreshToken(T user) throws RuntimeException;


    String refreshAccessToken(String refreshTokenJwt) throws RuntimeException;

    T verifyAccessToken(String jwt) throws RuntimeException;

    void invalidToken(String jwt) throws RuntimeException;

}
