package org.bty.blog.service.Impl;

import org.bty.blog.service.UserRoleService;
import org.springframework.stereotype.Service;

/**
 * @author bty
 * @date 2022/10/3
 * @since 1.8
 **/
@Service
public class UserRoleServiceImpl implements UserRoleService {
    @Override
    public void addRolesForUser(Integer userId, Integer... roleId) {
        // Todo add userId for every roleId
    }
}
