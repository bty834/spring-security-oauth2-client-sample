package com.example.authorization.repo;

import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.Arrays;
import java.util.List;

/**
 * @author bty
 * @date 2023/2/14
 * @since 17
 **/
public class CustomRegisteredClientRepository implements RegisteredClientRepository {

    private final RegisteredClientRepository proxy;

    public CustomRegisteredClientRepository(RegisteredClient... registrations) {
        this(Arrays.asList(registrations));
    }
    public CustomRegisteredClientRepository(List<RegisteredClient> registrations) {
        proxy= new InMemoryRegisteredClientRepository(registrations);
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        proxy.save(registeredClient);
    }

    @Override
    public RegisteredClient findById(String id) {
        return proxy.findById(id);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return proxy.findByClientId(clientId);
    }
}
