package com.duke.security.mvc;

import com.duke.common.base.utils.StringUtils;
import com.duke.mvc.utils.HttpResponseUtils;
import com.duke.security.common.JWTTokenUtils;
import com.duke.security.common.sys.user.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Component
public class AuthHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler, AuthenticationEntryPoint, AccessDeniedHandler, LogoutSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(AuthHandler.class);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        User user = (User) authentication.getPrincipal();
        try {
            response.addHeader("Access-Control-Expose-Headers", "Authorization");
            // 返回创建成功的token，只是单纯的token，按照jwt的规定，最后请求的时候应该是 `Bearer token`
            response.setHeader(HttpHeaders.AUTHORIZATION, JWTTokenUtils.generateToken(user));
//        response.setHeader(HttpHeaders.AUTHORIZATION, TokenUtils.generateToken(LoginUser.builder()
//                .id(user.getId())
//                .account(user.getAccount())
//                .name(user.getName())
//                .password(user.getPassword())
//                .departId(user.getDepartId())
//                .roleId(user.getRoleId())
//                .tenantId(user.getTenantId())
//                .accountNonExpired(user.isAccountNonExpired())
//                .accountNonLocked(user.isAccountNonLocked())
//                .credentialsNonExpired(user.isCredentialsNonExpired())
//                .enabled(user.isEnabled())
//                .role(user.getRole())
//                .depart(user.getDepart())
//                .tenant(user.getTenant())
//                .build()));
            HttpResponseUtils.okResponse(response);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            HttpResponseUtils.response(response, HttpStatus.INTERNAL_SERVER_ERROR, "服务器内部错误");
        }
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        log.info("登录失败：{}", request.getRequestURI() + " -- " + exception.getMessage());
        String message;
        if (exception instanceof UsernameNotFoundException) {
            message = "用户不存在";
        } else if (exception instanceof BadCredentialsException || exception instanceof AuthenticationCredentialsNotFoundException) {
            message = "用户/名密码不正确";
        } else if (exception instanceof LockedException) {
            message = "账户已锁定";
        } else if (exception instanceof AccountExpiredException) {
            message = "账户已过期";
        } else if (exception instanceof AccountStatusException) {
            message = "账户状态异常";
        } else {
            message = "登录失败";
        }
        HttpResponseUtils.response(response, HttpStatus.UNAUTHORIZED, StringUtils.isNotEmpty(exception.getMessage()) ? exception.getMessage() : "请登录");
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        exception.printStackTrace();
        log.info("用户未登录：{}", request.getRequestURI());
        HttpResponseUtils.response(response, HttpStatus.UNAUTHORIZED, StringUtils.isNotEmpty(exception.getMessage()) ? exception.getMessage() : "请登录");
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception) throws IOException {
        HttpResponseUtils.response(response, HttpStatus.FORBIDDEN, StringUtils.isNotEmpty(exception.getMessage()) ? exception.getMessage() : request.getMethod() + " " + request.getRequestURI() + "没有访问权限");
        log.info("没有访问权限：{}", request.getRequestURI());
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        HttpResponseUtils.okResponse(response);
        log.info("登出成功：{}", request.getRequestURI());
    }
}