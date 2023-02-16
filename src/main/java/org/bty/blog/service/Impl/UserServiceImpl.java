package org.bty.blog.service.Impl;

import lombok.RequiredArgsConstructor;
import org.bty.blog.entity.BlogUser;

import org.bty.blog.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientId;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;


import java.util.HashMap;
import java.util.Map;


/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    public static final Logger LOGGER = LoggerFactory.getLogger(UserServiceImpl.class);

    private final ClientRegistrationRepository registrationRepository;

    private final PasswordEncoder passwordEncoder;

    private final Map<OAuth2AuthorizedClientId, OAuth2AuthorizedClient> authorizedClients = new HashMap<>();

    @Override
    public BlogUser getUserByUsername(String username) {


        String encode = passwordEncoder.encode("123456") ;
        if(username.equals("bty"))
            return new BlogUser(1,"bty",encode);
        return new BlogUser(0, "nobody", "");
    }

    @Override
    public BlogUser addUser(String username, String password) {
        // TODO: add user in database
        return new BlogUser(0,username,password);
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
