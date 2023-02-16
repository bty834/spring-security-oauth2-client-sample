package com.example.blog.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.format.annotation.DateTimeFormat;

import java.util.Date;

/**
 * @author bty
 * @date 2023/2/11
 * @since 1.8
 **/
@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class CaptchaVO {

    private boolean enabled;
    private String uuid;
    private String base64Image;
    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private Date created;
}

