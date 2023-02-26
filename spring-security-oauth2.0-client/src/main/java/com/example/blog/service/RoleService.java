package com.example.blog.service;

import com.example.blog.entity.BlogRole;

/**
 * @author bty
 * @date 2022/10/2
 * @since 17
 **/
public interface RoleService {


    BlogRole addRole(String roleName, String[] permissions);

    BlogRole getRoleByName(String roleName);
}
