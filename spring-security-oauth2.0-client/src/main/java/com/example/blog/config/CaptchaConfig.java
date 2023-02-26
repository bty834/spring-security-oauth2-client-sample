package com.example.blog.config;

import com.google.code.kaptcha.Constants;
import com.google.code.kaptcha.impl.DefaultKaptcha;
import com.google.code.kaptcha.util.Config;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Properties;

/**
 * @author bty
 * @date 2023/2/11
 * @since 17
 **/
@Configuration
@EnableConfigurationProperties(CaptchaProperties.class)
public class CaptchaConfig {


    @Bean
    public Config captchaPicConfig(CaptchaProperties kp){
        Properties p = new Properties();
        p.setProperty(Constants.KAPTCHA_BORDER,kp.getBorder()?"yes":"no");
        p.setProperty(Constants.KAPTCHA_IMAGE_WIDTH,kp.getWidth());
        p.setProperty(Constants.KAPTCHA_IMAGE_HEIGHT,kp.getHeight());
        p.setProperty(Constants.KAPTCHA_TEXTPRODUCER_CHAR_LENGTH,kp.getCharLength());
        p.setProperty(Constants.KAPTCHA_TEXTPRODUCER_FONT_NAMES,kp.getFont());
        p.setProperty(Constants.KAPTCHA_TEXTPRODUCER_FONT_SIZE,kp.getFontSize());
        return new Config(p);
    }

    @Bean
    public DefaultKaptcha defaultKaptcha(Config config){
        DefaultKaptcha defaultKaptcha = new DefaultKaptcha();
        defaultKaptcha.setConfig(config);
        return defaultKaptcha;
    }
}
