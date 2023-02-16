package com.example.authorization.model;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * @author bty
 * @date 2023/2/14
 * @since 1.8
 **/
@Component
public class CustomPasswordEncoder extends BCryptPasswordEncoder {

    /**
     *
     * @param rawPassword base64encoded password
     * @return
     */
    @Override
    public String encode(CharSequence rawPassword) {

        return super.encode(rawPassword);
    }

    /**
     *
     * @param rawPassword base64encoded password
     * @param encodedPassword the encoded password from storage to compare with
     * @return
     */
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword cannot be null");
        }
        return super.matches(rawPassword,encodedPassword);
    }



    public static void main(String[] args) {


    }

}

