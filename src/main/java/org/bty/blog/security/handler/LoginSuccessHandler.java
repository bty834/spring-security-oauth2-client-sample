package org.bty.blog.security.handler;

import lombok.RequiredArgsConstructor;
import org.bty.blog.security.filter.BearTokenAuthenticationFilter;
import org.bty.blog.security.model.RedisUserDetail;
import org.bty.blog.service.TokenService;
import org.bty.blog.util.JacksonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8_VALUE;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 *
 * 普通用户名密码登录成功时的处理，记录登录状态并返回jwt
 **/
@Component
@RequiredArgsConstructor
public class LoginSuccessHandler implements AuthenticationSuccessHandler {
    private static final Logger logger = LoggerFactory.getLogger(LoginSuccessHandler.class);

    private final TokenService tokenService;

    /**
     *
     * @param request the request which caused the successful authentication
     * @param response the response
     * @param authentication 普通用户名密码登录时类型为 {@link UsernamePasswordAuthenticationToken}
     * the authentication process.
     * @throws IOException
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
            UserDetails user = (UserDetails)authentication.getPrincipal();

            RedisUserDetail redisUserDetail = new RedisUserDetail(user);
            // 关于登录信息存储，可以在SecurityContextRepository中完成
            String jwtToken = tokenService.initToken(redisUserDetail);

            logger.info("jwt {} for username-password login user {}",jwtToken,user);

            response.setContentType(APPLICATION_JSON_UTF8_VALUE);
            response.getWriter().write(
                    JacksonUtil.getObjectMapper().writeValueAsString(
                            ResponseEntity.ok(Collections.singletonMap("token", jwtToken))
                    )
            );
    }

}
