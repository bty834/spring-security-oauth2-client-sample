package org.bty.blog.entity;

import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
@Data
@NoArgsConstructor
@AllArgsConstructor
@ApiModel(value = "角色信息")
public class BlogRole {
    private Integer id;
    private String roleName;
    private String[] permissions;
}
