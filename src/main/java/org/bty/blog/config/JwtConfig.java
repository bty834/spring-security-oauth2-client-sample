package org.bty.blog.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import sun.security.rsa.RSAPublicKeyImpl;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

/**
 * @author bty
 * @date 2023/2/10
 * @since 1.8
 **/
@Configuration
public class JwtConfig {


    // 关于publickey的获取，可以直接放在jwt的header中的jwk字段
    // 或者在jwt的header中的jku字段放置获取jwk的uri,该地址必须TLS加密
    // 具体可参考rfc 7515 / rfc 7517 / rfc 7519
    @Value("${token.key.public}")
    RSAPublicKey key;

    @Value("${token.key.private}")
    RSAPrivateKey priv;

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(this.key).build();
    }

    @Bean
    public JWK jwk(){
        return new RSAKey.Builder(this.key).privateKey(this.priv).build();
    }

    @Bean
    public JwtEncoder jwtEncoder(List<JWK> jwkList) {
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwkList));
        return new NimbusJwtEncoder(jwks);
    }


}
