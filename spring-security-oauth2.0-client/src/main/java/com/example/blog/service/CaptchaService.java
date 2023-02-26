package com.example.blog.service;

import com.example.blog.entity.CaptchaVO;

/**
 * @author bty
 * @date 2023/2/11
 * @since 17
 **/
public interface CaptchaService {

    CaptchaVO getCaptcha();

    void verifyCaptcha(String uuid,String text);
}
