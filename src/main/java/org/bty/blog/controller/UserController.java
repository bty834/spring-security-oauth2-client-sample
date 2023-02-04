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


//    @GetMapping("/gitee")
//    public ResponseEntity<Map<String, Object>> gitee( @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,
//                        @AuthenticationPrincipal OAuth2User oauth2User) {
//        HashMap<String, Object> body = new HashMap<>();
//        body.put("authorizedClient",authorizedClient);
//        body.put("oauth2User",oauth2User);
//        return ResponseEntity.ok(body);
//    }
}
