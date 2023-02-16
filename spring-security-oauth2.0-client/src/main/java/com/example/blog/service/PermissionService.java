package com.example.blog.service;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
public interface PermissionService {


    String[] getPermissionsByUserId(Integer userId);

    void setPermission(Integer userId,String[] permissions);
}
