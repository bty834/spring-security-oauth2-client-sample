package com.example.blog.service;


import com.example.blog.security.model.SerializableToken;

/**
 * @author bty
 * @date 2022/10/2
 * @since 17
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
