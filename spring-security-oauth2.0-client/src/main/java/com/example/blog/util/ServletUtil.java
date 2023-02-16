package com.example.blog.util;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8_VALUE;

/**
 * @author bty
 * @date 2023/2/13
 * @since 1.8
 **/
public class ServletUtil {


    public static void successResponse(HttpServletResponse response, Map body) throws IOException {
        response.setContentType(APPLICATION_JSON_UTF8_VALUE);
        response.getWriter().write(
                JacksonUtil.getObjectMapper().writeValueAsString(
                        ResponseEntity.ok(body)
                )
        );
    }

    public static void failureResponse(HttpServletResponse response, String msg, HttpStatus httpStatus) throws IOException {
        response.setContentType(APPLICATION_JSON_UTF8_VALUE);
        response.getWriter().write(
                JacksonUtil.getObjectMapper().writeValueAsString(
                        ResponseEntity.status(httpStatus).body(Collections.singletonMap("msg", msg)))
        );
    }

}
