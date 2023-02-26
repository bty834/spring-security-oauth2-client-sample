package com.example.blog.service.Impl;

import com.example.blog.config.CaptchaProperties;
import com.example.blog.entity.CaptchaVO;
import com.example.blog.service.CaptchaService;
import com.google.code.kaptcha.impl.DefaultKaptcha;
import lombok.RequiredArgsConstructor;
import org.apache.tomcat.util.codec.binary.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * @author bty
 * @date 2023/2/11
 * @since 17
 **/
@Service
@RequiredArgsConstructor
public class CaptchaServiceImpl implements CaptchaService {
    public static final Logger LOGGER = LoggerFactory.getLogger(CaptchaServiceImpl.class);

    private final CaptchaProperties captchaProperties;
    private final DefaultKaptcha defaultKaptcha;

    private final RedisTemplate redisTemplate;

    private static final String CAPTCHA_KEY = "CAPTCHA:";

    public static String getCaptchaRedisKey(String uuid) {
        return CAPTCHA_KEY + uuid;
    }


    @Override
    public CaptchaVO getCaptcha() {
        if (!captchaProperties.getEnabled()) {
            return new CaptchaVO(captchaProperties.getEnabled(), null, null, new Date(System.currentTimeMillis()));
        }

        String text = defaultKaptcha.createText();

        String uuid = UUID.randomUUID().toString();

        redisTemplate.opsForValue().set(getCaptchaRedisKey(uuid), text, captchaProperties.getExpireSeconds(), TimeUnit.SECONDS);

        BufferedImage image = defaultKaptcha.createImage(text);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        try {
            ImageIO.write(image, "jpg", stream);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        String encodedImage = new String(Base64.encodeBase64(stream.toByteArray()), StandardCharsets.UTF_8);

        return new CaptchaVO(captchaProperties.getEnabled(), uuid, encodedImage, new Date(System.currentTimeMillis()));
    }

    @Override
    public void verifyCaptcha(String uuid,String text) {
        String answer = (String)redisTemplate.opsForValue().get(getCaptchaRedisKey(uuid));
        if(answer==null ){
            LOGGER.error("captcha expired");
            throw new BadCredentialsException("captcha expired");
        }
        if(!answer.equals(text)){
            LOGGER.error("captcha not matched");
            throw new BadCredentialsException("captcha not matched");
        }
    }
}
