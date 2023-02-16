package com.example.blog.security.handler;


///**
// * @author bty
// * @date 2022/10/3
// * @since 1.8
// * 第三方Oauth2.0 gitee登录成功时的处理，omit test
// **/
////@Component("oAuth2RestSuccessHandler")
//public class OAuth2RestSuccessHandler extends BaseRestSuccessHandler {
//
//
//    private static final Logger logger = LoggerFactory.getLogger(OAuth2RestSuccessHandler.class);
//
//    private UserService userService;
//
//
//    public OAuth2RestSuccessHandler(TokenService tokenService,UserService userService) {
//        super(tokenService);
//        this.userService = userService;
//    }
//
//
//    /**
//     * @param request        the request which caused the successful authentication
//     * @param response       the response
//     * @param authentication 第三方Oauth2.0 gitee登录时类型为 {@link OAuth2AuthenticationToken}
//     *                       the authentication process.
//     * @throws IOException
//     * @throws ServletException
//     */
//    @Override
//    public SerializableToken handlerLogin(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//        return ...;
//    }
//}
