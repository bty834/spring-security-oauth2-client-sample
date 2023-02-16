package com.example.blog.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
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
public class BlogUser {
    private Integer id;
    private String username;
    @JsonIgnore
    private transient String password;
}
