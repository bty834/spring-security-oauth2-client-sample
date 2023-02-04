package org.bty.blog.security.config;

import lombok.RequiredArgsConstructor;
import org.bty.blog.security.filter.BearTokenAuthenticationFilter;
import org.bty.blog.security.handler.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Collections;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
@Configuration
@EnableMethodSecurity()
@RequiredArgsConstructor
public class SecurityConfig {
    private static final String[] AUTH_WHITELIST = {

            // -- Swagger UI v2
            "/v2/api-docs",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
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

    private final LoginSuccessHandler loginSuccessHandler;
    private final LoginFailureHandler loginFailureHandler;
    private final OAuth2LoginSuccessHandler giteeSuccessHandler;

    private final CustomSessionAuthenticationStrategy customSessionAuthenticationStrategy;
    private final BearTokenAuthenticationFilter bearAuthenticationFilter;

    private final RestAccessDeniedHandler restAccessDeniedHandler;

    /**
     * 注意，在
     * @return {@link SecurityConfig#securityFilterChain(HttpSecurity http)}
     * 以上的方法中必须注明 {@code http.cors()}
     *
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


        http.csrf().disable();
        // 必须显式注明，配合CorsConfigurationSource的Bean，不然即使在web里面配置了跨域，security这里依然会cors error
        http.cors();
        http.authorizeRequests()
                .antMatchers(AUTH_WHITELIST).permitAll()
                .anyRequest().authenticated();

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

        // 前后端不分离，可指定html返回。该项未测试
        // http.formLogin().loginPage("login").loginProcessingUrl("/hello/login");

        // 前后端分离下username/password登录
        http.formLogin()
                .usernameParameter("userId")
                .passwordParameter("password")
                .loginProcessingUrl("/hello/login")
                .successHandler(loginSuccessHandler)
                .failureHandler(loginFailureHandler);
//                        .securityContextRepository()  // pass

        http.oauth2Login()
                .successHandler(giteeSuccessHandler).failureHandler(loginFailureHandler);
        http.exceptionHandling().accessDeniedHandler(restAccessDeniedHandler);


        http.addFilterBefore(bearAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * 对所有SecurityFilterChain做处理
     * @return
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        // 仅仅作为演示
        return (web) -> web.ignoring().antMatchers(AUTH_WHITELIST);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }




}
