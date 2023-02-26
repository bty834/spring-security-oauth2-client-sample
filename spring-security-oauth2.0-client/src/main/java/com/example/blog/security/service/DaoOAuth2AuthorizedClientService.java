package com.example.blog.security.service;

import com.example.blog.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 由 AuthenticatedPrincipalOAuth2AuthorizedClientRepository implements OAuth2AuthorizedClientRepository
 * 由 {@link AuthenticatedPrincipalOAuth2AuthorizedClientRepository AuthenticatedPrincipalOAuth2AuthorizedClientRepository implements OAuth2AuthorizedClientRepository}
 * 在 第三方认证成功后调用该类，默认实现 {@link InMemoryOAuth2AuthorizedClientService}
 *
 * 第三方登录成功，将登录的OAuth2用户记录到用户表,包含用户信息,accessToken,refreshToken <br/>
 * 这里作用其实就是保存授权服务器的accessToken和refreshToken<br/>
 * 因为在 {@link OAuth2LoginAuthenticationFilter#attemptAuthentication(HttpServletRequest, HttpServletResponse)}方法中<br/>
 * 将含有accessToken和refreshToken的 {@link OAuth2LoginAuthenticationToken} 转化为了不含有两个token的 {@link OAuth2AuthenticationToken}<br/>
 * 且 SecurityContext中保存的是后者，所以，为了保存accessToken、refreshToken等信息，需要在这个接口下操作
 *
 * @author bty
 * @date 2023/2/5
 * @since 17
 **/
@Component
@RequiredArgsConstructor
public class DaoOAuth2AuthorizedClientService implements OAuth2AuthorizedClientService {

    private final UserService userService;

    @Override
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
        return userService.loadAuthorizedClient(clientRegistrationId, principalName);
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        userService.saveAuthorizedClient(authorizedClient,principal);
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
        userService.removeAuthorizedClient(clientRegistrationId, principalName);
    }


}
