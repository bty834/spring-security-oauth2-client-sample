package com.example.blog.config;

import org.springframework.aop.interceptor.AsyncUncaughtExceptionHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.springframework.aop.interceptor.AsyncExecutionAspectSupport.DEFAULT_TASK_EXECUTOR_BEAN_NAME;

/**
 * @author bty
 * @date 2022/10/4
 * @since 17
 **/
@Configuration
@EnableAsync
public class AsyncConfig {

    public static final String LOG_TASK_EXECUTOR_BEAN_NAME = "logTaskExecutor";

    @Bean(name= DEFAULT_TASK_EXECUTOR_BEAN_NAME)
    public Executor taskExecutor() {
        // 自定义一个线程工厂只是为了给线程取一个我们自己的名字，别在意细节。
        return new ThreadPoolExecutor(2, 10, 60, TimeUnit.SECONDS, new ArrayBlockingQueue<>(100),
                r -> new Thread(r, "async-taskExecutor-" + r.hashCode()));
    }

    @Bean(name= LOG_TASK_EXECUTOR_BEAN_NAME)
    public Executor logTaskExecutor() {
        // 自定义一个线程工厂只是为了给线程取一个我们自己的名字，别在意细节。
        return new ThreadPoolExecutor(5, 10, 60, TimeUnit.SECONDS, new ArrayBlockingQueue<>(100),
                r -> new Thread(r, "async-logTaskExecutor-" + r.hashCode()));
    }

    @Bean
    public AsyncUncaughtExceptionHandler asyncUncaughtExceptionHandler(){
        return (ex, method, params) -> System.out.println(ex.getMessage());
    }



}
