package org.bty.blog.config;


import lombok.RequiredArgsConstructor;
import org.bty.blog.BlogApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

/**
 * @author bty
 * @date 2022/9/23
 * @since 1.8
 **/
@Configuration
@EnableSwagger2
@EnableConfigurationProperties(SwaggerProperties.class)
@RequiredArgsConstructor
public class Swagger2Config {

    private final SwaggerProperties properties;

    @Bean
    public Docket createRestApi() {

        return new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(new ApiInfoBuilder()
                        .title(properties.getTitle())//标题
                        .description(properties.getDescription()) //描述
                        .version(properties.getVersion()) //版本
                        .license(properties.getLicense())
                        .contact(new Contact(properties.getAuthor(), properties.getAuthorUrl(),properties.getEmail()))
                        .build()

                )
                .select()
                .apis(RequestHandlerSelectors.basePackage(BlogApplication.class.getPackage().getName()))//作用范围,在那个包下
                .paths(PathSelectors.any()) //指定包下所有请求
                .build();

    }
}
