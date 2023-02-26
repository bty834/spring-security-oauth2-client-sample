package com.example.blog.security.mapper;

import com.example.blog.security.model.SerializableOAuth2AuthorizationRequest;
import com.google.common.base.Strings;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.concurrent.TimeUnit;

/**
 * 用于保存正在进行 OAuth2 Login的client属性 <br/>
 * 比如在 {@link OAuth2AuthorizationRequestRedirectFilter} 中 保存 state和正在认证的client的信息到该repository中。<br/>
 * 在后来的 {@link OAuth2LoginAuthenticationFilter} 中会提取 state属性，并根据该state属性从该repository中获取，如果获取不到，表示可能存在CSRF攻击
 * @author bty
 * @date 2023/2/13
 * @since 17
 **/
@Component
@RequiredArgsConstructor
public class RedisAuthorizationRequestRepository implements AuthorizationRequestRepository {

    public static final String DEFAULT_INFLIGHT_REQUEST_REDIS_KEY_PREFIX = "OAUTH2_INFLIGHT_REQUEST:";

    private String redisKeyPrefix = DEFAULT_INFLIGHT_REQUEST_REDIS_KEY_PREFIX;

    private final RedisTemplate redisTemplate;

    public void setRedisKeyPrefix(String redisKeyPrefix) {
        this.redisKeyPrefix = redisKeyPrefix;
    }

    private String createRedisKey(String state){
        return this.redisKeyPrefix+state;
    }

    private String getStateParameter(HttpServletRequest request) {
        return request.getParameter(OAuth2ParameterNames.STATE);
    }


    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        String state = getStateParameter(request);
        if(Strings.isNullOrEmpty(state)){
            return null;
        }
        SerializableOAuth2AuthorizationRequest serializable = (SerializableOAuth2AuthorizationRequest)redisTemplate.opsForValue().get(createRedisKey(state));

        assert serializable != null;
        return SerializableOAuth2AuthorizationRequest.reverse(serializable);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        Assert.notNull(request, "request cannot be null");
        Assert.notNull(response, "response cannot be null");
        if (authorizationRequest == null) {
            this.removeAuthorizationRequest(request, response);
            return;
        }
        String state = authorizationRequest.getState();
        Assert.hasText(state, "authorizationRequest.state cannot be empty");

        SerializableOAuth2AuthorizationRequest adapt = SerializableOAuth2AuthorizationRequest.adapt(authorizationRequest);


        try {
            redisTemplate.opsForValue().set(createRedisKey(state),adapt,5, TimeUnit.MINUTES);
        } catch (Exception e) {
            throw new SessionAuthenticationException("In-flight Authorization Request store failed");
        }


    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request) {

        Assert.notNull(request, "request cannot be null");
        String state = this.getStateParameter(request);
        if(Strings.isNullOrEmpty(state)){
            return null;
        }
        try {
            SerializableOAuth2AuthorizationRequest serializable = (SerializableOAuth2AuthorizationRequest) redisTemplate.opsForValue().get(createRedisKey(state));
            redisTemplate.delete(createRedisKey(state));
            assert serializable != null;
            return SerializableOAuth2AuthorizationRequest.reverse(serializable);
        } catch (Exception e) {
            throw new SessionAuthenticationException(e.getMessage());
        }
    }


}
