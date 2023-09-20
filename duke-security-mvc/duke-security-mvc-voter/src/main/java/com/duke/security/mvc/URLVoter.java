package com.duke.security.mvc;

import com.duke.common.base.utils.CollectionUtils;
import com.duke.security.common.sys.resource.Resource;
import com.duke.security.common.sys.resource.ResourceService;
import com.duke.security.common.sys.user.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.RequestMethodsRequestCondition;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import javax.servlet.http.HttpServletRequest;
import java.math.BigDecimal;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;

@Component
public class URLVoter implements AccessDecisionVoter<Object> {
    private AntPathMatcher antMatcher = new AntPathMatcher();
    @javax.annotation.Resource
    private ResourceService resourceService;

    @Autowired
    private RequestMappingHandlerMapping mappingInfo;

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
//        return ACCESS_GRANTED;
        if (authentication == null) {
            return ACCESS_DENIED;
        }
        Object principal = authentication.getPrincipal();
        if (!(principal instanceof User)) {
            return ACCESS_DENIED;
        }
        try {
            User user = (User) principal;
            // 这里可以通过标记决定是使用缓存还是重新查库，以提升效率，由于请求路径中可能包含参数，所以不能使用request.getRequestURI()作为参数查询数据数据库
            // 更高效的方法是get=0,put=1,post=2,delete=4,patch=8,然后给每个url分配一个二进制数，用户登录时，计算其二进制的和
            List<Resource> resources = resourceService.queryResourcesByRoleId(user.getRoleId());
            FilterInvocation invocation = (FilterInvocation) object;
            HttpServletRequest request = invocation.getRequest();
            List<Resource> matchedResources = resources.stream().filter(resource -> match(resource, request)).toList();
            return CollectionUtils.isEmpty(matchedResources) ? ACCESS_DENIED : ACCESS_GRANTED;
//            Collection<? extends GrantedAuthority> authorities = extractAuthorities(authentication);
//            for (GrantedAuthority authority : authorities) {
//                if (authority instanceof Resource) {
//                    Resource resource = (Resource) authority;
//                    HandlerMethod handlerInternal = getHandlerInternal(((FilterInvocation) object).getRequest());
//                    Map<RequestMappingInfo, HandlerMethod> map = getHandlerMethods();
//                    for (RequestMappingInfo info : map.keySet()) {
//                        if (map.get(info).getMethod() == handlerInternal.getMethod() && match(info.getMethodsCondition(), info.getPatternsCondition(), resource)) {
//                            return ACCESS_GRANTED;
//                        }
//                    }
//                }
//            }
        } catch (Exception e) {
            e.printStackTrace();
            return ACCESS_DENIED;
        }
    }

    private boolean match(Resource resource, HttpServletRequest request) {
        boolean pathMatch = Arrays.stream(resource.getPathes().split(",")).anyMatch(path -> antMatcher.match(path, request.getRequestURI()));
        boolean methodMatch = Arrays.stream(resource.getMethodes().split(",")).anyMatch(item -> request.getMethod().equals(item));
        return pathMatch && methodMatch;
    }

    private boolean match(RequestMethodsRequestCondition methodsCondition, PatternsRequestCondition patternsCondition, Resource resource) {
        Set<RequestMethod> methods = methodsCondition.getMethods();
        Set<String> patterns = patternsCondition.getPatterns();
        for (String pattern : patterns) {
            if (Arrays.stream(resource.getPathes().split(",")).map(String::trim).anyMatch(item -> item.equals(pattern))) {
                for (RequestMethod method : methods) {
                    return Arrays.stream(resource.getMethodes().split(",")).map(String::trim).anyMatch(item -> item.equals(method.name()));
                }
            }
        }
        return false;
    }

    Collection<? extends GrantedAuthority> extractAuthorities(Authentication authentication) {
        return authentication.getAuthorities();
    }
}

