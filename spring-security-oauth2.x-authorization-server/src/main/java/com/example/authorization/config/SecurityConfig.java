package com.example.authorization.config;

import com.example.authorization.repo.CustomRegisteredClientRepository;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;
import java.util.function.Function;

/**
 * @author bty
 * @date 2023/2/14
 * @since 17
 **/
@Configuration
public class SecurityConfig {

    private final Function<OidcUserInfoAuthenticationContext, OidcUserInfo> oidcUserMapper;

    public SecurityConfig(Function<OidcUserInfoAuthenticationContext, OidcUserInfo> oidcUserMapper) {
        this.oidcUserMapper = oidcUserMapper;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {

        OAuth2AuthorizationServerConfigurer conf = new OAuth2AuthorizationServerConfigurer();
        // 注意，apply必须在自定义conf上面，否则会报错 securityBuilder is null
        http.apply(conf);


        //<editor-fold desc="自定义conf">

        conf
                // 存储正在进行验证的Authorization或已完成的Authorization
                // 后期验证accessToken和idToken都得用到，如果自定义，为Authorization设置过期时间，该时间不能小于accessToken的有效时长。
                .authorizationService(new InMemoryOAuth2AuthorizationService())
                // 存储OAuth2AuthorizationConsent，默认InMemory实现，只能在测试开发中使用
                .authorizationConsentService(new InMemoryOAuth2AuthorizationConsentService())
                // Enable OpenID Connect 1.0
                .oidc(configurer-> configurer
                        .userInfoEndpoint(
                                // 自定义用户信息查询逻辑
                                oidcUserInfoEndpointConfigurer -> oidcUserInfoEndpointConfigurer.userInfoMapper(oidcUserMapper)
                        )
                );


        //</editor-fold>





        RequestMatcher endpointsMatcher = conf.getEndpointsMatcher();

        http
                .requestMatcher(endpointsMatcher)
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))

                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/login"))
                )

                // Accept access tokens for User Info and/or Client Registration
                // Authorization server也有resource server，这里不用
                // 在另外一个包中使用spring-boot-starter-oauth2-resource-server实现
                 .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {


        http.authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());
        return http.build();
    }



    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {


        String encodeSecret = passwordEncoder.encode("test123");

        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("test")
                .clientSecret(encodeSecret)
                // secret校验方式
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/test")
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.OPENID)
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new CustomRegisteredClientRepository(registeredClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        // 以oauth2开头
        return AuthorizationServerSettings.builder()

                .authorizationEndpoint("/oauth2/authorize")
                .tokenEndpoint("/oauth2/token")
                // 用于资源服务器获取granted的accessToken信息进行验证
                .tokenIntrospectionEndpoint("/oauth2/introspect")
                // logout
                .tokenRevocationEndpoint("/oauth2/revoke")
                // 其他用户，包括资源服务器对jwt进行校验
                .jwkSetEndpoint("/oauth2/jwks")
                .oidcUserInfoEndpoint("/oauth2/userinfo")
                .oidcClientRegistrationEndpoint("/oauth2/connect/register")
                .build();
    }

    @Bean
    public TokenSettings authorizationTokenSettings(){
        return TokenSettings.builder()
                // 如果重写OAuth2AuthorizationService，重写类的存储时长请和accessToken保持一致
                .accessTokenTimeToLive(Duration.ofMinutes(5))
                .refreshTokenTimeToLive(Duration.ofDays(1))
                .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                .reuseRefreshTokens(true)
                .build();

    }

    @Bean
    public ClientSettings clientSettings(){
        return ClientSettings.builder()
                .requireAuthorizationConsent(true)
                // 禁用PKCE
                .requireProofKey(false)
                .build();
    }
}
