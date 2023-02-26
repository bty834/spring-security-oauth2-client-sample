package com.example.blog.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author bty
 * @date 2023/2/11
 * @since 17
 **/
@ConfigurationProperties("captcha")
@AllArgsConstructor
@NoArgsConstructor
@Data
public class CaptchaProperties {

    private Boolean enabled ;
    private Boolean border;
    private String width ;
    private String height;
    private String fontSize;
    private String charLength;
    private String font;
    private Integer expireSeconds;
}
