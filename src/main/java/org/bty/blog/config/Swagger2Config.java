package org.bty.blog.config;


import com.github.xiaoymin.knife4j.spring.annotations.EnableKnife4j;
import lombok.RequiredArgsConstructor;
import org.bty.blog.BlogApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
@EnableKnife4j
@RequiredArgsConstructor
public class Swagger2Config {


    @Bean
    public Docket createRestApi() {

        return new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(new ApiInfoBuilder()
                        .title("Spring Security OAuth2.0 Example")//标题
                        .description("desc") //描述
                        .version("v1") //版本
                        .license("MIT")
                        .contact(new Contact("bty","http://localhost/","2300175122@qq.com"))
                        .build()

                )
                .select()
                .apis(RequestHandlerSelectors.basePackage(BlogApplication.class.getPackage().getName()))//作用范围,在那个包下
                .paths(PathSelectors.any()) //指定包下所有请求
                .build();

    }
}
