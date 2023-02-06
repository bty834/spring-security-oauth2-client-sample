package org.bty.blog.service;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
public interface TokenService {

    /**
     * including accessToken and refreshToken
     * @param user
     * @return
     */
    String createAccessToken(Object user);
    String createRefreshToken(Object user);


    String refreshAccessToken(String refreshTokenJwt);

    Object verifyAccessToken(String jwt);

}
