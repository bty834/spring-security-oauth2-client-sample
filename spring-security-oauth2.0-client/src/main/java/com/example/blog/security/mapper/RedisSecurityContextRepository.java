package com.example.blog.security.mapper;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.session.SessionManagementFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.function.Supplier;

/**
 * {@link SecurityContextRepository}的作用是为了防止 Session Fixation Attack
 *
 * 即提供一个暂存SecurityContext和 Session的对应关系
 * 从未认证状态至认证状态，需要更换session。
 *
 *
 * 该功能由 {@link SessionManagementFilter}完成
 * @author bty
 * @date 2023/2/5
 * @since 1.8
 **/
//@Component
public class RedisSecurityContextRepository implements SecurityContextRepository {
    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        return null;
    }

    @Override
    public Supplier<SecurityContext> loadContext(HttpServletRequest request) {
        return SecurityContextRepository.super.loadContext(request);
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {

    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return false;
    }
}
