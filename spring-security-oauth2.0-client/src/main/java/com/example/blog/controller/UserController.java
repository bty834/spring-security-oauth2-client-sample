package com.example.blog.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

/**
 * @author bty
 * @date 2022/10/3
 * @since 17
 **/

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {


    private final UserDetailsManager manager;

    /**
     * 必须登录才能访问
     * @return
     */
    @GetMapping("/test")
    public ResponseEntity<Map<String, Object>> gogo() {
        return ResponseEntity.ok(Collections.singletonMap("msg","u logged in"));
    }

    /**
     * {@link EnableMethodSecurity} 注解必须配置在配置类上<br/>
     * {@link PreAuthorize}等注解中表达式使用 Spring EL
     * @return
     */
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public ResponseEntity<Map<String, Object>> admin() {

        return ResponseEntity.ok(Collections.singletonMap("msg","u r admin"));
    }


}
