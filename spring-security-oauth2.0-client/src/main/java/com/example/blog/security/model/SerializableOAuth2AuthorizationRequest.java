package com.example.blog.security.model;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.io.Serializable;
import java.util.Map;
import java.util.Set;

/**
 * @author bty
 * @date 2023/2/13
 * @since 17
 **/
public class SerializableOAuth2AuthorizationRequest implements Serializable {

    private String authorizationUri;

    private String authorizationGrantType;

    private String responseType;

    private String clientId;

    private String redirectUri;

    private Set<String> scopes;

    private String state;

    private Map<String, Object> additionalParameters;

    private String authorizationRequestUri;

    private Map<String, Object> attributes;

    public SerializableOAuth2AuthorizationRequest() {
    }

    public String getAuthorizationUri() {
        return authorizationUri;
    }

    public void setAuthorizationUri(String authorizationUri) {
        this.authorizationUri = authorizationUri;
    }

    public String getAuthorizationGrantType() {
        return authorizationGrantType;
    }

    public void setAuthorizationGrantType(String authorizationGrantType) {
        this.authorizationGrantType = authorizationGrantType;
    }

    public String getResponseType() {
        return responseType;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public Map<String, Object> getAdditionalParameters() {
        return additionalParameters;
    }

    public void setAdditionalParameters(Map<String, Object> additionalParameters) {
        this.additionalParameters = additionalParameters;
    }

    public String getAuthorizationRequestUri() {
        return authorizationRequestUri;
    }

    public void setAuthorizationRequestUri(String authorizationRequestUri) {
        this.authorizationRequestUri = authorizationRequestUri;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    public static SerializableOAuth2AuthorizationRequest adapt(OAuth2AuthorizationRequest request) {
        SerializableOAuth2AuthorizationRequest serializable = new SerializableOAuth2AuthorizationRequest();
        serializable.setAuthorizationUri(request.getAuthorizationUri());
        serializable.setAuthorizationGrantType(request.getGrantType().getValue());
        serializable.setResponseType(request.getResponseType().getValue());
        serializable.setClientId(request.getClientId());
        serializable.setRedirectUri(request.getRedirectUri());
        serializable.setScopes(request.getScopes());
        serializable.setState(request.getState());
        serializable.setAdditionalParameters(request.getAdditionalParameters());
        serializable.setAuthorizationRequestUri(request.getAuthorizationRequestUri());
        serializable.setAttributes(request.getAttributes());
        return serializable;
    }

    public static OAuth2AuthorizationRequest reverse(SerializableOAuth2AuthorizationRequest serializable) {
        OAuth2AuthorizationRequest.Builder requestBuilder;
        if (serializable.getAuthorizationGrantType().equals(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())) {
            requestBuilder = OAuth2AuthorizationRequest.authorizationCode();

        } else {
            requestBuilder = OAuth2AuthorizationRequest.implicit();
        }
        requestBuilder.authorizationUri(serializable.getAuthorizationUri())
                .clientId(serializable.getClientId())
                .redirectUri(serializable.getRedirectUri())
                .scopes(serializable.getScopes())
                .state(serializable.getState())
                .additionalParameters(serializable.getAdditionalParameters())
                .authorizationRequestUri(serializable.getAuthorizationRequestUri())
                .attributes(serializable.getAttributes());

        return requestBuilder.build();
    }

}
