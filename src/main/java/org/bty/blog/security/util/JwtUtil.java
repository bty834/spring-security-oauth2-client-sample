package org.bty.blog.security.util;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/

public class JwtUtil {



    public static String encode(Map<String ,Object> payload,Integer expireMinutes,String secret){
        return JWT.create()
                .withExpiresAt(new Date(System.currentTimeMillis() + (long) expireMinutes * 60 * 1000))
                .withIssuer("bty")
                .withPayload(payload)
                .sign(Algorithm.HMAC256(secret));
    }

    public static Map<String, Claim> decode (String jwt, String secret) throws JWTVerificationException {
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secret)).build();
        DecodedJWT decodedJWT = verifier.verify(jwt);
        return decodedJWT.getClaims();
    }


}
