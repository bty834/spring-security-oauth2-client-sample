package org.bty.blog.service;

import org.bty.blog.entity.BlogUser;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
public interface UserService {



    BlogUser getUserByUsername(String username);


    BlogUser addUser(String username,String password);
}
