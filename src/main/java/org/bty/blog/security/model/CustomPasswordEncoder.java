package org.bty.blog.security.model;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * @author bty
 * @date 2023/2/14
 * @since 1.8
 **/
public class CustomPasswordEncoder extends BCryptPasswordEncoder {
    @Override
    public String encode(CharSequence rawPassword) {

        return super.encode(decodeBase64Password(rawPassword));
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword cannot be null");
        }
        return super.matches(decodeBase64Password(rawPassword),encodedPassword);
    }

    private static String decodeBase64Password(CharSequence base64RawPassword){
        String s = base64RawPassword.toString();
        byte[] decode = Base64.getDecoder().decode(s.getBytes(StandardCharsets.UTF_8));
        return new String(decode,StandardCharsets.UTF_8);
    }
    private static String encodeBase64Password(CharSequence rawPassword){

        byte[] bytes = rawPassword.toString().getBytes(StandardCharsets.UTF_8);
        byte[] encode = Base64.getEncoder().encode(bytes);
        return new String(encode,StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        System.out.println(encodeBase64Password("123456"));
    }

}
