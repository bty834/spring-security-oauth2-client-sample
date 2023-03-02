package com.example.authorization.repo;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.function.Function;

/**
 * authorization server返回accessToken和idToken后，client会请求userinfo_uri，<br/>
 * client请求会携带accessToken，然后authorization server会利用resource server的 {@link BearerTokenAuthenticationFilter} 去认证用户<br/>
 * 认证成功后 由 {@link OidcUserInfoAuthenticationProvider}根据Authentication完成用户信息的查询，查询使用该{@link Function<OidcUserInfoAuthenticationContext, OidcUserInfo>}接口实现类完成
 *
 * @author bty
 * @date 2023/2/16
 * @since 17
 **/
@Component
public class CustomOidcUserInfoMapper implements Function<OidcUserInfoAuthenticationContext, OidcUserInfo> {

    /**
     * 		 https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
     * 			1) The sub (subject) Claim MUST always be returned in the UserInfo Response
     * 			    if (userInfo.getSubject() == null) {
     * 				    OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE);
     * 				    throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
     *                        }
     * 			2) Due to the possibility of token substitution attacks (see Section
     * 			    16.11),
     * 			 the UserInfo Response is not guaranteed to be about the End-User
     * 			 identified by the sub (subject) element of the ID Token.
     * 			 The sub Claim in the UserInfo Response MUST be verified to exactly match
     * 			 the sub Claim in the ID Token; if they do not match,
     * 			 the UserInfo Response values MUST NOT be used.
     * @param oidcUserInfoAuthenticationContext the function argument
     * @return
     */
    @Override
    public OidcUserInfo apply(OidcUserInfoAuthenticationContext oidcUserInfoAuthenticationContext) {
        Authentication authentication = oidcUserInfoAuthenticationContext.getAuthentication();
        Map<String, Object> claims = new HashMap<>();

        Object principal = authentication.getPrincipal();

        if(principal instanceof JwtAuthenticationToken token){
            claims.put("name",token.getName());
            claims.put("sub",token.getName());

        }
        claims.put("email","baotingyu1997@gmail.com");
        claims.put("blog","btyhub.site");
        return new OidcUserInfo(claims);
    }
}
