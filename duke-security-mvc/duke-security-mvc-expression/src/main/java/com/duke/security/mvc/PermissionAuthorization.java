package com.duke.security.mvc;

import com.duke.common.base.utils.CollectionUtils;
import com.duke.security.common.sys.resource.Resource;
import com.duke.security.common.sys.resource.ResourceService;
import com.duke.security.common.sys.user.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.condition.PathPatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.RequestMethodsRequestCondition;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import javax.servlet.http.HttpServletRequest;
import java.math.BigDecimal;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

@Component("PermissionAuthorization")
public class PermissionAuthorization {
    private AntPathMatcher antMatcher = new AntPathMatcher();
    @Autowired
    private RequestMappingHandlerMapping mappingInfo;

    @javax.annotation.Resource
    private ResourceService resourceService;

    public boolean authorize(HttpServletRequest request, Authentication authentication) {
        Object principal = authentication.getPrincipal();
        if (!(principal instanceof User)) {
            return false;
        }
        try {
            User user = (User) principal;
            // 这里可以通过标记决定是使用缓存还是重新查库，以提升效率，由于请求路径中可能包含参数，所以不能使用request.getRequestURI()作为参数查询数据数据库
            // 更高效的方法是get=0,put=1,post=2,delete=4,patch=8,然后给每个url分配一个二进制数，用户登录时，计算其二进制的和
            List<Resource> resources = resourceService.queryResourcesByRoleId(user.getRoleId());
            List<Resource> matchedResources = resources.stream().filter(resource -> match(resource, request)).toList();
            return CollectionUtils.isNotEmpty(matchedResources);
//            if (CollectionUtils.isEmpty(matchedResources)) {
//                return false;
//            }
//            return mappingInfo.getHandlerMethods().keySet().stream().anyMatch(requestMappingInfo -> match(requestMappingInfo.getMethodsCondition(), requestMappingInfo.getPathPatternsCondition(), matchedResources));
        } catch (Exception e) {
            e.printStackTrace();
            throw new AccessDeniedException(request.getMethod() + " " + request.getRequestURI());
        }
    }

    private boolean match(Resource resource, HttpServletRequest request) {
        boolean pathMatch = Arrays.stream(resource.getPathes().split(",")).anyMatch(path -> antMatcher.match(path, request.getRequestURI()));
        boolean methodMatch = Arrays.stream(resource.getMethodes().split(",")).anyMatch(item -> request.getMethod().equals(item));
        return pathMatch && methodMatch;
    }

    private boolean match(RequestMethodsRequestCondition methodsCondition, PathPatternsRequestCondition pathPatternsCondition, List<Resource> resources) {
        if (pathPatternsCondition == null) {
            return false;
        }
        // 先看路径是否匹配，如果路径不匹配直接返回false
        Set<RequestMethod> methods = methodsCondition.getMethods();
        Set<String> patterns = pathPatternsCondition.getPatternValues();
        for (Resource resource : resources) {
            for (String pattern : patterns) {
                if (Arrays.stream(resource.getPathes().split(",")).map(String::trim).anyMatch(item -> item.equals(pattern))) {
                    for (RequestMethod method : methods) {
                        if (Arrays.stream(resource.getMethodes().split(",")).map(String::trim).anyMatch(item -> item.equals(method.name()))) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }
}