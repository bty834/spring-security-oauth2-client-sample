package org.bty.blog.controller;

import io.swagger.annotations.Api;
import org.bty.blog.entity.BlogUser;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @author bty
 * @date 2022/10/3
 * @since 1.8
 **/
@Api("user")
@RestController
@RequestMapping("/user")
public class UserController {


    @GetMapping
    public ResponseEntity<BlogUser> getUser(){
        return ResponseEntity.ok(new BlogUser(1,"bty","123456"));
    }
}
