package org.bty.blog.security.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;

import org.bty.blog.config.CaptchaProperties;
import org.bty.blog.security.converter.BearerTokenResolver;
import org.bty.blog.security.filter.BearerTokenAuthenticationFilter;
import org.bty.blog.security.filter.CaptchaVerifyFilter;
import org.bty.blog.security.handler.*;
import org.bty.blog.security.model.CustomPasswordEncoder;
import org.bty.blog.service.CaptchaService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
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


    @Value("${login.uri}")
    private String loginUri;

    @Value("${logout.uri}")
    private String logoutUri;

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


    private final AuthenticationFailureHandler restFailureHandler;

    private final AuthenticationSuccessHandler restSuccessHandler;

    private final CaptchaService captchaService;

    private final OAuth2AuthorizedClientService daoOAuth2AuthorizedClientService;

    private final SessionAuthenticationStrategy customSessionAuthenticationStrategy;

    private final AccessDeniedHandler restAccessDeniedHandler;
    private final AuthenticationEntryPoint restAuthenticationEntrypoint;

    private final BearerTokenResolver bearerTokenResolver;

    private final AuthenticationManager jwtAuthenticationManager;

    private final AuthorizationRequestRepository authorizationRequestRepository;

    private final GrantedAuthoritiesMapper grantedAuthoritiesMapper;

    private final LogoutSuccessHandler logoutSuccessHandler;
    private final LogoutHandler logoutHandler;


    @Value("${captcha.enabled}")
    private boolean captchaEnabled;

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
                .antMatchers("/token/**").permitAll()
//                //访问 /.well-known/change-password 默认重定向到 /change-password
//                .antMatchers("/**/change-password").permitAll()
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
                .usernameParameter("username")
                .passwordParameter("password")
                // 最好以/login开头，涉及其他地方判断
                .loginProcessingUrl(loginUri)
                .successHandler(restSuccessHandler)
                .failureHandler(restFailureHandler);
//                        .securityContextRepository()  // pass

//        http.userDetailsService(userDetailsService); // 只需将自定义userDetailsService注入容器，这行可以不写


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

        // 拿取code的uri模式默认为：/oauth2/authorization/{registration_id}
        // code换取accessToken和refreshToken的uri模式默认为：/login/oauth2/code/{registration_id}
        http.oauth2Login()
                .authorizationEndpoint()
                .authorizationRequestRepository(authorizationRequestRepository);
        http.oauth2Login()
                .successHandler(restSuccessHandler)
                .failureHandler(restFailureHandler)
                // 开始认证，默认 /oauth2/authorization/{registration_id} 不要带后面{}的东西
                .authorizationEndpoint().baseUri("/oauth2/auth")
                .and()
                // 后端接受code的地址，拿到code去换accessToken和userInfo，默认 /login/oauth2/code/* 星号不能省略，使用AntMatch，参见 AbstractAuthenticationProcessingFilter#setFilterProcessesUrl
                .redirectionEndpoint().baseUri("/login/oauth2/code/*")
//                .and()
//                .tokenEndpoint().accessTokenResponseClient() //
//                .and()
//                .userInfoEndpoint().userAuthoritiesMapper().userService()

//                // 针对认证成功的用户，调用OAuth2AuthorizedClientRepository的
//                // 默认实现类AuthenticatedPrincipalOAuth2AuthorizedClientRepository中的
//                // OAuth2AuthorizedClientService (默认Inmemory)存储
//                // 否则
//                // 匿名存储调用OAuth2AuthorizedClientRepository的另一个实现类用session存储
//                .authorizedClientRepository(...)
                .and()
                .authorizedClientService(daoOAuth2AuthorizedClientService);

        http.logout()
                .logoutUrl(logoutUri)
                .addLogoutHandler(logoutHandler)
                .logoutSuccessHandler(logoutSuccessHandler)
                .invalidateHttpSession(true);

        // extract bearer token to verify if the user has logged in
        // before logout filter, to logout needs user logged in
        http.addFilterBefore(new BearerTokenAuthenticationFilter(restAuthenticationEntrypoint, bearerTokenResolver, jwtAuthenticationManager, restFailureHandler), OAuth2AuthorizationRequestRedirectFilter.class);


        CaptchaVerifyFilter captchaVerifyFilter = new CaptchaVerifyFilter(loginUri, captchaService, restFailureHandler);
        captchaVerifyFilter.setCaptchaEnabled(captchaEnabled);
        // username password登录之前先校验captcha
        http.addFilterBefore(captchaVerifyFilter, UsernamePasswordAuthenticationFilter.class);


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
        return new CustomPasswordEncoder();
    }


}
