package org.bty.blog.security.handler;


import org.bty.blog.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 * <p>
 * 普通用户名密码登录成功时的处理，记录登录状态并返回jwt
 **/
@Component("restSuccessHandler")
public class RestSuccessHandler extends BaseLoginRestSuccessHandler {
    private static final Logger logger = LoggerFactory.getLogger(RestSuccessHandler.class);

    public RestSuccessHandler(TokenService tokenService) {
        super(tokenService);
    }


    /**
     * @param request        the request which caused the successful authentication
     * @param response       the response
     * @param authentication 普通用户名密码登录时类型为 {@link UsernamePasswordAuthenticationToken}
     *                       the authentication process.
     * @throws IOException
     */
    @Override
    public Object handlerLogin(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        return authentication;
    }

}
