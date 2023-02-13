package org.bty.blog.controller;

import com.google.common.base.Strings;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.bty.blog.service.TokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.bind.annotation.*;

import java.security.interfaces.RSAPublicKey;
import java.util.*;
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

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(@RequestBody String refreshToken) {

        if(Strings.isNullOrEmpty(refreshToken)){
            return ResponseEntity.ok(Collections.singletonMap("msg","no refreshToken or invalid refreshToken"));
        }
        String accessToken = tokenService.refreshAccessToken(refreshToken);
        return ResponseEntity.ok(Collections.singletonMap("accessToken",accessToken));
    }


    private final List<JWK> jwkList;

    /**
     * 获取JWK校验JWT的api <br/>
     * 链接必须基于TLS，本案例未配置
     */
    @GetMapping("/keys")
    public ResponseEntity<Map<String, Object>> keys(){
        List<Map<String, Object>> keys = jwkList.stream().map(JWK::toJSONObject).collect(Collectors.toList());
        return  ResponseEntity.ok(Collections.singletonMap("keys",keys));
    }

}
