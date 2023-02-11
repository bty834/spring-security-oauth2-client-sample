package org.bty.blog.service;

import org.bty.blog.entity.CaptchaVO;

/**
 * @author bty
 * @date 2023/2/11
 * @since 1.8
 **/
public interface CaptchaService {

    CaptchaVO getCaptcha();

    void verifyCaptcha(String uuid,String text);
}
