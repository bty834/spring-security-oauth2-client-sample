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
@ApiModel(value = "用户角色对应关系")
public class User2Role {
    private Integer id;
    private Integer userId;
    private Integer roleId;
}
