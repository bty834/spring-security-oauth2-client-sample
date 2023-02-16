package com.example.blog.service.Impl;


import com.example.blog.provider.TokenPersistProvider;
import com.example.blog.security.model.SerializableToken;
import com.example.blog.service.TokenService;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
@Service
@RequiredArgsConstructor
public class JwtServiceImpl implements TokenService {
    private static final Logger logger = LoggerFactory.getLogger(JwtServiceImpl.class);

    private static final String UUID_CLAIM = "uuid";

    @Value("${token.access-token-expire-minutes}")
    private Integer accessTokenExpireMinutes;

    @Value("${token.refresh-token-expire-minutes}")
    private Integer refreshTokenExpireMinutes;


    private final TokenPersistProvider tokenPersistProvider;

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;

    private String getAccessTokenRedisKey(String uuid) {
        return "ACCESS_TOKEN" + ":" + uuid;
    }

    private String getRefreshTokenRedisKey(String uuid) {
        return "REFRESH_TOKEN" + ":" + uuid;
    }

    @Override
    public  String createAccessToken(SerializableToken user) throws RuntimeException{
        String uuid = UUID.randomUUID().toString();
        tokenPersistProvider.persist(getAccessTokenRedisKey(uuid),user,accessTokenExpireMinutes,TimeUnit.MINUTES);
        return generateJwt(UUID_CLAIM, uuid, accessTokenExpireMinutes);
    }

    /**
     * refreshToken可以不为jwt，uuid就可以
     * @param user
     * @return
     * @throws RuntimeException
     */
    @Override
    public String createRefreshToken(SerializableToken user) throws RuntimeException{
        String uuid = UUID.randomUUID().toString();
        tokenPersistProvider.persist(getRefreshTokenRedisKey(uuid),user,accessTokenExpireMinutes,TimeUnit.MINUTES);
        return generateJwt(UUID_CLAIM, uuid, refreshTokenExpireMinutes);

    }

    private String generateJwt(String name, String token, Integer expireMinutes) {
        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
//                .issuer()
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expireMinutes * 60))
                .claim(name, token)
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }


    @Override
    public String refreshAccessToken(String jwt) throws RuntimeException{
        Jwt decode = jwtDecoder.decode(jwt);
        String refreshToken = decode.getClaim(UUID_CLAIM);
        SerializableToken user = tokenPersistProvider.get(getRefreshTokenRedisKey(refreshToken),refreshTokenExpireMinutes,TimeUnit.MINUTES);
        return createAccessToken(user);
    }


    @Override
    public SerializableToken verifyAccessToken(String jwt) throws RuntimeException{
        Jwt decode = jwtDecoder.decode(jwt);
        String uuid = decode.getClaim(UUID_CLAIM);
        return tokenPersistProvider.get(getAccessTokenRedisKey(uuid),accessTokenExpireMinutes,TimeUnit.MINUTES);
    }

    @Override
    public void invalidToken(String jwt) throws RuntimeException {
        Jwt decode = jwtDecoder.decode(jwt);
        String uuid = decode.getClaim(UUID_CLAIM);
        tokenPersistProvider.invalid(getAccessTokenRedisKey(uuid));
    }


}
