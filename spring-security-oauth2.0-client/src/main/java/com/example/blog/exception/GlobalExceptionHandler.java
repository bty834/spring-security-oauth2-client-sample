package com.example.blog.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Collections;
import java.util.Optional;

/**
 * @author bty
 * @date 2023/3/8
 * @since 17
 **/
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler
    public ResponseEntity exceptionHandler(Exception e){
        return ResponseEntity.of(Optional.of(Collections.singletonMap("msg",e.getMessage())));
    }
}
