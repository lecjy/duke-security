package com.duke.security.reactive;

import com.duke.common.base.utils.StringUtils;
import com.duke.security.common.JWTTokenUtils;
import com.duke.security.common.sys.user.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Component
public class ReactiveAuthHandler implements ServerAuthenticationSuccessHandler, ServerAuthenticationFailureHandler, ServerAccessDeniedHandler, ServerAuthenticationEntryPoint, ServerLogoutSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(ReactiveAuthHandler.class);

    // 登录成功响应
    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange exchange, Authentication authentication) {
        User user = (User) authentication.getPrincipal();
        ServerHttpRequest request = exchange.getExchange().getRequest();
        ServerHttpResponse response = exchange.getExchange().getResponse();
        try {
//            response.addHeader("Access-Control-Expose-Headers", "Authorization");
            // 返回创建成功的token，只是单纯的token，按照jwt的规定，最后请求的时候应该是 `Bearer token`
            response.getHeaders().add(HttpHeaders.AUTHORIZATION, JWTTokenUtils.generateToken(user));
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
            return ReactiveResponseUtils.okResponse(response);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return ReactiveResponseUtils.response(response, HttpStatus.INTERNAL_SERVER_ERROR, "服务器内部错误", false);
        }
    }

    @Override
    public Mono<Void> onAuthenticationFailure(WebFilterExchange exchange, AuthenticationException exception) {
        ServerHttpRequest request = exchange.getExchange().getRequest();
        ServerHttpResponse response = exchange.getExchange().getResponse();
        log.info("登录失败：{}", request.getURI().getPath() + " -- " + exception.getMessage());
        String message;
        if (exception instanceof UsernameNotFoundException) {
            message = "用户不存在";
        } else if (exception instanceof BadCredentialsException || exception instanceof AuthenticationCredentialsNotFoundException) {
            message = "用户/名密码不正确";
        } else if (exception instanceof LockedException) {
            message = "账户已锁定";
        } else if (exception instanceof AccountExpiredException || exception instanceof CredentialsExpiredException) {
            message = "账户已过期";
        } else if (exception instanceof DisabledException) {
            message = "账户已禁用";
        } else if (exception instanceof AccountStatusException) {
            message = "账户状态异常";
        } else {
            message = "登录失败";
        }
        return ReactiveResponseUtils.response(response, HttpStatus.UNAUTHORIZED, message, false);
    }

    // 已登录访问无权限资源响应
    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException exception) {
        ServerHttpRequest request = exchange.getRequest();
        log.info("没有访问权限：{}", request.getURI().getPath());
        return ReactiveResponseUtils.response(exchange.getResponse(), HttpStatus.FORBIDDEN, StringUtils.isNotEmpty(exception.getMessage()) ? exception.getMessage() : request.getMethod() + " " + request.getURI().getPath() + "没有访问权限", false);
    }

    // 登出成功响应
    @Override
    public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
        log.info("登出成功：{}", exchange.getExchange().getRequest().getURI().getPath());
        return ReactiveResponseUtils.okResponse(exchange.getExchange().getResponse());
    }

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException exception) {
        exception.printStackTrace();
        log.info("用户未登录：{}", exchange.getRequest().getURI().getPath());
        return ReactiveResponseUtils.response(exchange.getResponse(), HttpStatus.UNAUTHORIZED, StringUtils.isNotEmpty(exception.getMessage()) ? exception.getMessage() : "请登录", false);
    }
}