package org.bty.blog.security.service;

import lombok.RequiredArgsConstructor;
import org.bty.blog.entity.BlogUser;
import org.bty.blog.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.stereotype.Component;

/**
 * 由 AuthenticatedPrincipalOAuth2AuthorizedClientRepository implements OAuth2AuthorizedClientRepository
 * 由 {@link AuthenticatedPrincipalOAuth2AuthorizedClientRepository AuthenticatedPrincipalOAuth2AuthorizedClientRepository implements OAuth2AuthorizedClientRepository}
 * 在 第三方认证成功后调用该类，默认实现 {@link InMemoryOAuth2AuthorizedClientService}
 *
 * 这里的作用是，第三方登录成功，将首次登录的用户记录到用户表
 * @author bty
 * @date 2023/2/5
 * @since 1.8
 **/
@Component
@RequiredArgsConstructor
public class DaoOAuth2AuthorizedClientService implements OAuth2AuthorizedClientService {

    private final UserService userService;

    @Override
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
        BlogUser user = userService.getUserByUsername(principalName);
        return (T) transferFromBlogUser(user);
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        userService.addUser(authorizedClient.getPrincipalName(), (String)principal.getCredentials());
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
//        userService.deleteUser();
    }

    private OAuth2AuthorizedClient transferFromBlogUser(BlogUser blogUser){
        // omit
        return null;
    }
}
