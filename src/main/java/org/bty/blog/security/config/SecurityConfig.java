package org.bty.blog.security.config;

import lombok.RequiredArgsConstructor;
import org.bty.blog.security.converter.BearAuthenticationConverter;
import org.bty.blog.security.filter.BearAuthenticationFilter;
import org.bty.blog.security.handler.LoginSuccessHandler;
import org.bty.blog.security.handler.OAuth2LoginSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
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
    private final OAuth2LoginSuccessHandler giteeSuccessHandler;

    private final BearAuthenticationFilter bearAuthenticationFilter;
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
        http.authorizeRequests()
                .antMatchers(AUTH_WHITELIST).permitAll()
                .anyRequest().authenticated();

        http.formLogin().successHandler(loginSuccessHandler);

        http.oauth2Login().successHandler(giteeSuccessHandler);

        http.addFilterBefore(bearAuthenticationFilter, BasicAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }




}
