package org.bty.blog.security.handler;

import org.bty.blog.security.model.SerializableToken;
import org.bty.blog.service.TokenService;
import org.bty.blog.util.JacksonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;

import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8_VALUE;

/**
 * @author bty
 * @date 2023/2/6
 * @since 1.8
 **/
abstract public class BaseRestSuccessHandler implements AuthenticationSuccessHandler {
    private static final Logger logger = LoggerFactory.getLogger(BaseRestSuccessHandler.class);

    private final TokenService tokenService;

    public BaseRestSuccessHandler(TokenService tokenService) {
        this.tokenService = tokenService;
    }



    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        SerializableToken o = handlerLogin(request, response, authentication);

        // 关于登录信息存储，可以在SecurityContextRepository中完成
        String accessToken = tokenService.createAccessToken(o);
        String refreshToken = tokenService.createRefreshToken(o);

        logger.info("accessToken: {} and refreshToken: {} for login user {}", accessToken, refreshToken, o);

        HashMap<String, String> body = new HashMap<>();
        body.put("accessToken", accessToken);
        body.put("refreshToken", refreshToken);
        response.setContentType(APPLICATION_JSON_UTF8_VALUE);
        response.getWriter().write(
                JacksonUtil.getObjectMapper().writeValueAsString(
                        ResponseEntity.ok(body)
                )
        );
    }

    abstract public SerializableToken handlerLogin(HttpServletRequest request, HttpServletResponse response, Authentication authentication);
}
