package org.bty.blog.service;

import org.bty.blog.entity.BlogRole;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
public interface RoleService {


    BlogRole addRole(String roleName,String[] permissions);

    BlogRole getRoleByName(String roleName);
}
