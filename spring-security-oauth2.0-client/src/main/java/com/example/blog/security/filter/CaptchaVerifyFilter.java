package com.example.blog.security.filter;

import com.example.blog.service.CaptchaService;
import com.google.common.base.Strings;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author bty
 * @date 2023/2/11
 * @since 17
 **/
@RequiredArgsConstructor
public class CaptchaVerifyFilter extends OncePerRequestFilter {

    public static final String SPRING_SECURITY_FORM_UUID_KEY = "uuid";
    public static final String SPRING_SECURITY_FORM_CAPTCHA_KEY = "captcha";

    private String uuidKey = SPRING_SECURITY_FORM_UUID_KEY;
    private String inputKey = SPRING_SECURITY_FORM_CAPTCHA_KEY;

    private boolean captchaEnabled = false;
    private final String loginUri;
    private final CaptchaService captchaService;
    private final AuthenticationFailureHandler failureHandler;



    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 不是登录，直接跳过
        if(!captchaEnabled || !request.getServletPath().equals(loginUri)){
            filterChain.doFilter(request,response);
            return;
        }
        try {
            verifyCaptcha(request,response);
            // 成功之后继续
            filterChain.doFilter(request,response);
        } catch (AuthenticationException e) {
            SecurityContextHolder.clearContext();
            // 错误直接返回
            failureHandler.onAuthenticationFailure(request,response,e);
        }
    }

    public void verifyCaptcha(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        String uuid = obtainUuid(request);
        String captcha = obtainCaptcha(request);

        if(Strings.isNullOrEmpty(uuid) || Strings.isNullOrEmpty(captcha)){
            throw new BadCredentialsException("captcha null or empty");
        }

        captchaService.verifyCaptcha(uuid,captcha);

    }


    protected String obtainUuid(HttpServletRequest request) {
        return request.getParameter(this.uuidKey);
    }

    protected String obtainCaptcha(HttpServletRequest request) {
        return request.getParameter(this.inputKey);
    }

    public void setUuidKey(String uuidKey) {
        this.uuidKey = uuidKey;
    }

    public void setInputKey(String inputKey) {
        this.inputKey = inputKey;
    }

    public void setCaptchaEnabled(boolean captchaEnabled) {
        this.captchaEnabled = captchaEnabled;
    }
}
