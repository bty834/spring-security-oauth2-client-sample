package org.bty.blog.service.Impl;

import lombok.RequiredArgsConstructor;
import org.bty.blog.entity.BlogUser;
import org.bty.blog.service.UserService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * @author bty
 * @date 2022/10/2
 * @since 1.8
 **/
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {



    @Override
    public BlogUser getUserByUsername(String username) {

        String encode = new BCryptPasswordEncoder().encode("123456");
        if(username.equals("bty"))
            return new BlogUser(1,"bty",encode);
        return new BlogUser(0, "nobody", "");
    }

    @Override
    public BlogUser addUser(String username, String password) {
        // ToDo add user in database
        return new BlogUser(2,username,password);
    }


}
