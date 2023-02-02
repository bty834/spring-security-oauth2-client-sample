package org.bty.blog.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
@Data
@NoArgsConstructor
@AllArgsConstructor
@ApiModel(value = "用户信息")
public class BlogUser {
    private Integer id;
    private String username;
    @JsonIgnore
    private transient String password;
}
