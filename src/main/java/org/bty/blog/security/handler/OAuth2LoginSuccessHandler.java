package org.bty.blog.security.handler;

import lombok.RequiredArgsConstructor;

import org.bty.blog.security.model.RedisOAuth2User;

import org.bty.blog.service.TokenService;

import org.bty.blog.util.JacksonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8_VALUE;

/**
 * @author bty
 * @date 2022/10/3
 * @since 1.8
 * 第三方Oauth2.0 gitee登录成功时的处理
 **/
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {


    private static final Logger logger = LoggerFactory.getLogger(OAuth2LoginSuccessHandler.class);

    private final TokenService tokenService;



    /**
     * @param request        the request which caused the successful authentication
     * @param response       the response
     * @param authentication 第三方Oauth2.0 gitee登录时类型为 {@link OAuth2AuthenticationToken}
     *                       the authentication process.
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

                OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
                OAuth2User oAuth2User = token.getPrincipal();

                // async，可在DaoOAuth2AuthorizedClientService中完成该工作
                // tokenService.completeUserInfo(token,oAuth2User);


                RedisOAuth2User redisOAuth2User = new RedisOAuth2User(oAuth2User, token.getAuthorizedClientRegistrationId());
                // store session and generate jwt
                String jwtToken = tokenService.initToken(redisOAuth2User);
                logger.info("jwt {} for oauth2.0 login user {}",jwtToken,oAuth2User);

                response.setContentType(APPLICATION_JSON_UTF8_VALUE);
                response.getWriter().write(
                        JacksonUtil.getObjectMapper().writeValueAsString(
                                ResponseEntity.ok(Collections.singletonMap("token", jwtToken))
                        )
                );

    }
}
