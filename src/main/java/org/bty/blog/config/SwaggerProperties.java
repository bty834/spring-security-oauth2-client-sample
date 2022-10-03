package org.bty.blog.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author bty
 * @date 2022/9/26
 * @since 1.8
 **/

@ConfigurationProperties(prefix = "swagger")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SwaggerProperties {
    private String title;
    private String version;
    private String description;
    private String license;
    private String author;
    private String authorUrl;
    private String email;
}
