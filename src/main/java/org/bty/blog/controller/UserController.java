package org.bty.blog.controller;

import com.google.common.base.Strings;
import io.swagger.annotations.Api;
import lombok.RequiredArgsConstructor;
import org.bty.blog.entity.BlogUser;
import org.bty.blog.security.converter.BearerTokenResolver;
import org.bty.blog.service.TokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
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
@RequiredArgsConstructor
public class UserController {

    private final TokenService tokenService;

    private final BearerTokenResolver bearerTokenResolver;

    /**
     * 必须登录才能访问
     * @return
     */
    @GetMapping("/test")
    public ResponseEntity<Map<String, Object>> gitee() {
        HashMap<String, Object> body = new HashMap<>();
        body.put("msg","u win");
        return ResponseEntity.ok(body);
    }

    /**
     * 必须登录才能访问
     * @return
     */
    @GetMapping("/refreshAccessToken")
    public ResponseEntity<Map<String, Object>> refresh(String refreshToken) {
        HashMap<String, Object> body = new HashMap<>();

        if(Strings.isNullOrEmpty(refreshToken)){
            body.put("msg","no refreshToken or invalid refreshToken");
            return ResponseEntity.ok(body);
        }
        body.put("token",tokenService.refreshAccessToken(refreshToken));
        return ResponseEntity.ok(body);
    }
}
