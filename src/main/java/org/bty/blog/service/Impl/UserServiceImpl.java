package org.bty.blog.service.Impl;

import lombok.RequiredArgsConstructor;
import org.bty.blog.entity.BlogRole;
import org.bty.blog.entity.BlogUser;
import org.bty.blog.service.RoleService;
import org.bty.blog.service.UserRoleService;
import org.bty.blog.service.UserService;
import org.omg.CORBA.PRIVATE_MEMBER;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientId;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.aop.interceptor.AsyncExecutionAspectSupport.DEFAULT_TASK_EXECUTOR_BEAN_NAME;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final ClientRegistrationRepository registrationRepository;

    private final Map<OAuth2AuthorizedClientId, OAuth2AuthorizedClient> authorizedClients = new HashMap<>();

    @Override
    public BlogUser getUserByUsername(String username) {

        String encode = new BCryptPasswordEncoder().encode("123456");
        if(username.equals("bty"))
            return new BlogUser(1,"bty",encode);
        return new BlogUser(0, "nobody", "");
    }

    @Override
    public BlogUser addUser(String username, String password) {
        // TODO: add user in database
        return new BlogUser();
    }

    // 仿照 InMemoryOAuth2AuthorizedClientService
    @Override
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
        Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        ClientRegistration registration = registrationRepository.findByRegistrationId(clientRegistrationId);
        if(registration == null) {
            return null;
        }
        return (T) this.authorizedClients.get(new OAuth2AuthorizedClientId(clientRegistrationId, principalName));
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        Assert.notNull(authorizedClient, "authorizedClient cannot be null");
        Assert.notNull(principal, "principal cannot be null");
        this.authorizedClients.put(new OAuth2AuthorizedClientId(
                authorizedClient.getClientRegistration().getRegistrationId(), principal.getName()), authorizedClient);
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
        this.authorizedClients.remove(new OAuth2AuthorizedClientId(clientRegistrationId, principalName));
    }


}
