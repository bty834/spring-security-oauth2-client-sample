package org.bty.blog.security.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;

import org.bty.blog.security.filter.BearerTokenAuthenticationFilter;
import org.bty.blog.security.handler.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
@Configuration
@EnableMethodSecurity(securedEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {


    @Value("${token.key.public}")
    RSAPublicKey key;

    @Value("${token.key.private}")
    RSAPrivateKey priv;


    private static final String[] AUTH_WHITELIST = {

            // -- Swagger UI v2
            "/v2/api-docs",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/**",

            // 注意swagger2
            // 3.0.0版本之前访问/swagger-ui.html
            // 3.0.0版本之后访问/swagger-ui/index.html
            // 但是我升到3.0.0版本security一直报403,不知道什么原因
            // 降到2.9.2就正常访问了
            "/swagger-ui.html",
            "/swagger-ui/index.html",
            "/webjars/**",
            // -- Swagger UI v3 (OpenAPI)
            "/v3/api-docs/**",
            "/swagger-ui/**",

            // knife4j 访问的首页地址
            "/doc.html"
    };


    private final RestSuccessHandler restSuccessHandler;
    private final AuthenticationFailureHandler restFailureHandler;
    private final OAuth2RestSuccessHandler oAuth2SuccessHandler;


    private final OAuth2AuthorizedClientService daoOAuth2AuthorizedClientService;

    private final SessionAuthenticationStrategy customSessionAuthenticationStrategy;

    private final AccessDeniedHandler restAccessDeniedHandler;
    private final AuthenticationEntryPoint restAuthenticationEntrypoint;

    private final BearerTokenAuthenticationFilter bearerTokenAuthenticationFilter;

    /**
     * 注意，在
     *
     * @return {@link SecurityConfig#securityFilterChain(HttpSecurity http)}
     * 以上的方法中必须注明 {@code http.cors()}
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.setAllowedOrigins(Collections.singletonList("*"));
        corsConfig.setAllowedMethods(Collections.singletonList("*"));
        corsConfig.setAllowedHeaders(Collections.singletonList("*"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);
        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // 前后端分离可以禁用
        http.csrf().disable();
        // 必须显式注明，配合CorsConfigurationSource的Bean，不然即使在web里面配置了跨域，security这里依然会cors error
        http.cors();

        // antMatcher or mvcMatcher
        http.authorizeHttpRequests()
                .antMatchers(AUTH_WHITELIST).permitAll()
                // hasRole中不需要添加 ROLE_前缀
                // ant 匹配 /admin /admin/a /admin/a/b 都会匹配上
                .antMatchers("/admin/**").hasRole("ADMIN")
                // 剩下的需要认证
                .anyRequest().authenticated();
                // denyAll慎用
//                .anyRequest().denyAll();

//        http.authorizeHttpRequests()
//                .mvcMatchers(AUTH_WHITELIST).permitAll()
//                        // 效果同上
//                        .mvcMatchers("/admin").hasRole("ADMIN")
//                        .anyRequest().denyAll();

        // 设置登录成功后session处理, 认证成功后
        // SessionAuthenticationStrategy的最早执行，详见AbstractAuthenticationProcessingFilter
        // 执行顺序：
        // 1. SessionAuthenticationStrategy#onAuthentication
        // 2. SecurityContextHolder#setContext
        // 3. SecurityContextRepository#saveContext
        // 4. RememberMeServices#loginSuccess
        // 5. ApplicationEventPublisher#publishEvent
        // 6. AuthenticationSuccessHandler#onAuthenticationSuccess
        http.sessionManagement().sessionAuthenticationStrategy(customSessionAuthenticationStrategy);


        http.exceptionHandling().accessDeniedHandler(restAccessDeniedHandler);
        http.exceptionHandling().authenticationEntryPoint(restAuthenticationEntrypoint);
        // TODO http.securityContext().securityContextRepository(...);

        // 前后端不分离，可指定html返回。该项未测试
        // http.formLogin().loginPage("login").loginProcessingUrl("/hello/login");

        // 前后端分离下username/password登录
        http.formLogin()
                .usernameParameter("userId")
                .passwordParameter("password")
                // 最好以/login开头，涉及其他地方判断
                .loginProcessingUrl("/login/yeah")
                .successHandler(restSuccessHandler)
                .failureHandler(restFailureHandler);
//                        .securityContextRepository()  // pass


        // OAuth2AuthorizationRequestRedirectFilter:
        // 根据路径匹配，默认 /oauth2/authorization/{registration_id},如果匹配上，表示开始第三方登录
        // 即，这个filter是用来获取authorization_code的。
        // 第三方应用返回是否授权页面给浏览器，用户同意后，authorization_code会返回给该应用前端，前端将code返回给后端
        // 前端地址为redirect_url，须在第三方应用配置，也要再本应用配置，两个要相同。
        // 这里为了方便演示，这个redirect_url我直接设成后端地址，跳过了前端传回后端步骤，而这个接受的后端地址格式
        // 默认必须是 /login/oauth2/code/{registration_id}?code=code&state=state。

        // OAuth2LoginAuthenticationFilter:
        // 包含两部分：1. 拿着authorization_code去第三方授权服务器换取 accessToken  2. 拿着 accessToken去第三方资源服务器换取资源信息 (底层使用restTemplate)
        // OAuth2LoginAuthenticationFilter 通过 OAuth2LoginAuthenticationProvider 执行 操作
        // OAuth2LoginAuthenticationProvider 中有个 OAuth2AuthorizationCodeAuthenticationProvider ，后者专门用于 code换取accessToken操作
        // OAuth2LoginAuthenticationProvider在OAuth2AuthorizationCodeAuthenticationProvider 获取到accessToken基础上执行 accessToken换取资源信息操作
        http.oauth2Login()
                .successHandler(oAuth2SuccessHandler)
                .failureHandler(restFailureHandler)
// TODO
//                // 开始认证访问的地址，获取authorization 的 url，一般通过yaml配置
//                .authorizationEndpoint(authorizationEndpointConfig -> authorizationEndpointConfig.baseUri("url"))
//                // 授权服务器 返回authorization_code的回调地址一般通过yaml配置
//                .redirectionEndpoint(redirectionEndpointConfig -> redirectionEndpointConfig.baseUri("url"))
//                // authorization_code 交换accessToken的 url ,一般通过yaml配置
//                .tokenEndpoint(tokenEndpointConfig -> tokenEndpointConfig.accessTokenResponseClient())
//                // 获取用户授权信息，一般通过yaml配置
//                .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig.userService())
//                // 针对认证成功的用户，调用OAuth2AuthorizedClientRepository的
//                // 默认实现类AuthenticatedPrincipalOAuth2AuthorizedClientRepository中的
//                // OAuth2AuthorizedClientService (默认Inmemory)存储
//                // 否则
//                // 匿名存储调用OAuth2AuthorizedClientRepository的另一个实现类用session存储
//                .authorizedClientRepository(...)
                .authorizedClientService(daoOAuth2AuthorizedClientService);


// TODO
//        http
//              .logout(logout -> logout
//                        .logoutUrl("/my/logout")
//                        .logoutSuccessUrl("/my/index")
//                        .logoutSuccessHandler(logoutSuccessHandler)
//                        .invalidateHttpSession(true)
//                        .addLogoutHandler(logoutHandler)
//                        .deleteCookies(cookieNamesToClear)
//                );

        // extract bearer token to verify if the user has logged in
        http.addFilterBefore(bearerTokenAuthenticationFilter, OAuth2AuthorizationRequestRedirectFilter.class);


        return http.build();
    }

    /**
     * 对所有SecurityFilterChain做处理
     *
     * @return
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        // 仅仅作为演示
        return (web) -> web.ignoring().antMatchers(AUTH_WHITELIST);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }



    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(this.key).build();
    }

    @Bean
    JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(this.key).privateKey(this.priv).build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

}
