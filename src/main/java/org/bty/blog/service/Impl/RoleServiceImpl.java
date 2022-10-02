package org.bty.blog.service.Impl;

import org.bty.blog.entity.BlogRole;
import org.bty.blog.service.RoleService;
import org.springframework.stereotype.Service;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
@Service
public class RoleServiceImpl implements RoleService {
    /**
     * roleName一定要以 ROLE_ 开头
     * @param roleName
     * @return
     */
    @Override
    public BlogRole addRole(String roleName,String[] permissions) {
        // Todo add role
        return new BlogRole(2,roleName,permissions);
    }

    @Override
    public BlogRole getRoleByName(String roleName) {
        return new BlogRole(4,roleName,new String[]{"test"});
    }
}
