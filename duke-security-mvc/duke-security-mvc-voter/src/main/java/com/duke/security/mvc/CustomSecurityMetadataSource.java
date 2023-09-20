package com.duke.security.mvc;

import com.duke.security.common.sys.resource.ResourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Collection;

@Component
public class CustomSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {
    @Autowired
    ResourceService resourceService;

    AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        // AbstractSecurityInterceptor#rejectPublicInvocations属性默认为false，表示当getAttributes方法返回null时，允许访问受保护对象
        String uri = ((FilterInvocation) object).getRequest().getRequestURI();
        // 这里其实没用到
        return SecurityConfig.createList(((FilterInvocation) object).getRequest().getMethod() + " " + uri);
//        List<Resource> resources = resourceService.queryResourcesByRoleId(SecurityContextUtils.currentUserId());
//        for (Resource resourc : resources) {
//            if (pathMatcher.match(resourc.getPattern(), uri)) {
//                return SecurityConfigurer.createList(resourc.getPattern());
//            }
//        }
//        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }
}