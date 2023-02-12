package org.bty.blog.service;

import org.bty.blog.entity.BlogUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
public interface UserService {



    BlogUser getUserByUsername(String username);

    BlogUser addUser(String username,String password);


    <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName);

    void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal);

    void removeAuthorizedClient(String clientRegistrationId, String principalName);

}
