package org.bty.blog.security.util;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Date;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
@Component
@NoArgsConstructor
public class JwtUtil {

    @Value("${token.expire-minutes}")
    private Integer expireMinutes;

    @Value("${token.secret}")
    private String secret;


    public String encodeUUID(String uuid)  {
        return JWT.create()
                .withExpiresAt(new Date(System.currentTimeMillis() + (long) expireMinutes * 60 * 1000))
                .withSubject(uuid)
                .sign(Algorithm.HMAC256(secret));
    }

    public String decodeUUID (String accessToken) {

        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secret)).build();
        DecodedJWT decodedJWT = verifier.verify(accessToken);
        return decodedJWT.getSubject();

    }
}
