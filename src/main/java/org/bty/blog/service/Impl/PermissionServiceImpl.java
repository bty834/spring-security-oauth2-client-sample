package org.bty.blog.service.Impl;

import org.bty.blog.service.PermissionService;
import org.springframework.stereotype.Service;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
@Service
public class PermissionServiceImpl implements PermissionService {
    @Override
    public String[] getPermissionsByUserId(Integer userId) {
        return new String[]{"read","write","execute"};
    }

    @Override
    public void setPermission(Integer userId, String[] permissions) {

    }
}
