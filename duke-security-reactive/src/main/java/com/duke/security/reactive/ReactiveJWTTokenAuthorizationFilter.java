package com.duke.security.reactive;

import com.duke.common.base.utils.StringUtils;
import com.duke.security.common.JWTTokenUtils;
import com.duke.security.common.sys.user.User;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Collections;

public class ReactiveJWTTokenAuthorizationFilter implements WebFilter {

    public static final String HEADER_PREFIX = "Bearer ";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String bearerToken = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        // TODO 如果请求头中没有Authorization信息则直接放行了
        if (StringUtils.isEmpty(bearerToken)) {
//            HttpResponseUtils.unauthorizedResponse(response, "token不能为空");
            return chain.filter(exchange);
        }
        String token = bearerToken;
        if (bearerToken.startsWith(HEADER_PREFIX)) {
            token = bearerToken.substring(7);
        }
        try {
            // 如果请求头中有token，则进行解析，并且设置认证信息
            User user = JWTTokenUtils.userInfo(token);
            //为了保持持久化登录重新设置 security 的 authentication 登录信息验证
//            ReactiveSecurityContextHolder.withAuthentication(new UsernamePasswordAuthenticationToken(user, user.getId(), Collections.emptyList()));
            return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(new UsernamePasswordAuthenticationToken(user, user.getId(), Collections.emptyList())));
        } catch (Exception e) {
            e.printStackTrace();
            return ReactiveResponseUtils.unauthorizedResponse(exchange.getResponse(), StringUtils.isNotEmpty(e.getMessage()) ? e.getMessage() : "请登录");
        }
    }
}
