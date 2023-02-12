package org.bty.blog.security.handler;



import org.bty.blog.service.TokenService;

import org.bty.blog.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * @author bty
 * @date 2022/10/3
 * @since 1.8
 * 第三方Oauth2.0 gitee登录成功时的处理，omit test
 **/
//@Component("oAuth2RestSuccessHandler")
public class OAuth2RestSuccessHandler extends BaseRestSuccessHandler {


    private static final Logger logger = LoggerFactory.getLogger(OAuth2RestSuccessHandler.class);

    private UserService userService;


    public OAuth2RestSuccessHandler(TokenService tokenService,UserService userService) {
        super(tokenService);
        this.userService = userService;
    }


    /**
     * @param request        the request which caused the successful authentication
     * @param response       the response
     * @param authentication 第三方Oauth2.0 gitee登录时类型为 {@link OAuth2AuthenticationToken}
     *                       the authentication process.
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public Object handlerLogin(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = token.getPrincipal();

        // async，可在DaoOAuth2AuthorizedClientService中完成该工作
        userService.addUser(token, oAuth2User);

        return authentication;
    }
}
