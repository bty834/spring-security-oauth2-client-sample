package com.example.blog.controller;

import com.example.blog.service.TokenService;
import com.google.common.base.Strings;
import com.nimbusds.jose.jwk.JWK;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author bty
 * @date 2023/2/11
 * @since 1.8
 **/
@RestController
@RequestMapping("/token")
@RequiredArgsConstructor
public class TokenController {

    private final TokenService tokenService;
    private final List<JWK> jwkList;

    /**
     * refresh token , 参照OAuth2规范 <br/>
     * 地址：<a href="https://www.rfc-editor.org/rfc/rfc6749#page-47">rfc6749: Refreshing an Access Token</a> <br/>
     * 参数形式为: x-www-form-urlencoded
     * @param refreshToken
     * @param grantType 必须为 refresh_token
     * @return
     */
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(@RequestParam("refresh_token") String refreshToken, @RequestParam("grant_type")String grantType) {

        if (Strings.isNullOrEmpty(refreshToken) || Strings.isNullOrEmpty(grantType) || !grantType.equals(OAuth2ParameterNames.REFRESH_TOKEN)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Collections.singletonMap("msg", "grantType not supported"));
        }

        String accessToken = tokenService.refreshAccessToken(refreshToken);
        return ResponseEntity.ok(Collections.singletonMap("accessToken", accessToken));
    }


    /**
     * 获取JWK校验JWT的api <br/>
     * 链接必须基于TLS，本案例未配置
     */
    @GetMapping("/keys")
    public ResponseEntity<Map<String, Object>> keys() {
        List<Map<String, Object>> keys = jwkList.stream().map(JWK::toJSONObject).collect(Collectors.toList());
        return ResponseEntity.ok(Collections.singletonMap("keys", keys));
    }

}
