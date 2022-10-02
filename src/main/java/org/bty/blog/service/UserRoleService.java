package org.bty.blog.service;

/**
 * @author bty
 * @date 2022/10/3
 * @since 1.8
 * user role 对应关系表
 * id user_id role_id
 **/
public interface UserRoleService {

    void addRolesForUser(Integer userId,Integer... roleId);
}
