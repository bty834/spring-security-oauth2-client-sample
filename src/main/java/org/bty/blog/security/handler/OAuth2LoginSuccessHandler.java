package org.bty.blog.security.handler;

import lombok.RequiredArgsConstructor;
import org.bty.blog.entity.BlogRole;
import org.bty.blog.entity.BlogUser;
import org.bty.blog.service.RoleService;
import org.bty.blog.service.TokenService;
import org.bty.blog.service.UserRoleService;
import org.bty.blog.service.UserService;
import org.bty.blog.util.JacksonUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

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


    private final UserService userService;
    private final UserRoleService userRoleService;
    private final RoleService roleService;
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
        DefaultOAuth2User oAuth2User = (DefaultOAuth2User) token.getPrincipal();

        // 为每个第三方平台登录的创建一个角色，如ROLE_GITEE
        String roleName = "ROLE_" + token.getAuthorizedClientRegistrationId().toUpperCase();
        BlogRole role = roleService.getRoleByName(roleName);
        if (role == null) {
            Collection<? extends GrantedAuthority> authorities = oAuth2User.getAuthorities();
            List<String> permissions = new ArrayList<>();
            authorities.forEach(grantedAuthority -> {
                permissions.add(grantedAuthority.getAuthority());
            });
            role = roleService.addRole(roleName, permissions.toArray(new String[0]));
        }


        String username = oAuth2User.getName();
        // 没有用户创建用户
        BlogUser user = userService.getUserByUsername(username);
        if (user == null) {
            user = userService.addUser(username, null);
        }

        // 加入用户角色对应关系
        userRoleService.addRolesForUser(user.getId(), role.getId());


        // 创建jwt
        String jwtToken = tokenService.initToken(token);
        response.setContentType(APPLICATION_JSON_UTF8_VALUE);
        response.getWriter().write(
                JacksonUtil.getObjectMapper().writeValueAsString(
                        ResponseEntity.ok(Collections.singletonMap("token", jwtToken))
                )
        );

    }
}
