package org.bty.blog.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
@RestController
@RequestMapping
public class HomeController {


    /**
     * 重写了OAuth2登录的successhandler,获取到资源后就不会redirect到这里。
     * 默认的OAuth2的successhandler为 {@link SavedRequestAwareAuthenticationSuccessHandler}，这里面最后会跳到“/”的uri
     * @param authorizedClient
     * @param oauth2User
     * @return
     */
    @GetMapping
    public ResponseEntity<Map<String, Object>> homeOauth(@RegisteredOAuth2AuthorizedClient("gitee") OAuth2AuthorizedClient authorizedClient,
                                              @AuthenticationPrincipal OAuth2User oauth2User){
        Map<String, Object> map = new HashMap<>();
        map.put("authorizedClient",authorizedClient);
        map.put("oauth2User",oauth2User);
        return ResponseEntity.ok(map);
    }
}
