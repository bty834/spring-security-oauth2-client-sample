package org.bty.blog.service;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
public interface TokenService {

    String initToken(Object user);

    Object verifyToken(String jwt);

    void completeUserInfo(OAuth2AuthenticationToken token, OAuth2User oAuth2User);
}
