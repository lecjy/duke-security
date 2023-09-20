package com.duke.security.mvc;

import com.duke.common.base.utils.StringUtils;
import com.duke.mvc.utils.HttpResponseUtils;
import com.duke.security.common.JWTTokenUtils;
import com.duke.security.common.sys.user.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

public class JWTTokenAuthorizationFilter extends BasicAuthenticationFilter {

    @Autowired
    public JWTTokenAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String token = request.getHeader("Authorization");
        // TODO 如果请求头中没有Authorization信息则直接放行了
        if (StringUtils.isEmpty(token)) {
//            HttpResponseUtils.unauthorizedResponse(response, "token不能为空");
            chain.doFilter(request, response);
            return;
        }
        try {
            // 如果请求头中有token，则进行解析，并且设置认证信息
            User user = JWTTokenUtils.userInfo(token);
            //为了保持持久化登录重新设置 security 的 authentication 登录信息验证
            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(user, user.getId(), Collections.emptyList()));
            chain.doFilter(request, response);
        } catch (Exception e) {
            HttpResponseUtils.unauthorizedResponse(response, StringUtils.isNotEmpty(e.getMessage()) ? e.getMessage() : "请登录");
        }
    }
}
/**
 * 控制token销毁？使用redis+token组合，不仅解析token，还判断redis是否有这个token。注销和主动失效token：删除redis的key
 * <p>
 * 控制token过期时间？如果用户在token过期前1秒还在操作，下1秒就需要重新登录，肯定不好
 * <p>
 * 1、考虑加入refreshToken，过期时间比token长，前端在拿到token的同时获取过期时间，在过期前一分钟用refreshToken调用refresh接口，重新获取新的token。
 * <p>
 * 2、 将返回的jwtToken设置短一点的过期时间，redis再存这个token，过期时间设置长一点。如果请求过来token过期，查询redis，如果redis还存在，返回新的token。（为什么redis的过期时间大于token的？因为redis的过期是可控的，手动可删除，以redis的为准）
 * <p>
 * 每次请求都会被OncePerRequestFilter拦截，每次都会被UserDetailService中的获取用户数据请求数据库
 * 可以考虑做缓存，还是用redis或者直接保存内存中
 * <p>
 * 针对上面的2.2，也就是redis时间久一点，jwt过期后如果redis没过期，颁发新的jwt。不过更推荐的是前端判断过期时间，在过期之前调用refresh接口拿到新的jwt。
 * <p>
 * 为什么这样？
 * <p>
 * 如果redis过期时间是一周，jwt是一个小时，那么一个小时后，拿着这个过期的jwt去调，就可以想创建多少个新的jwt就创建，只要没过redis的过期时间。当然这是在没对过期的jwt做限制的情况下，如果要考虑做限制，比如对redis的value加一个字段，保存当前jwt，刷新后就用新的jwt覆盖，refresh接口判断当前的过期jwt是不是和redis这个一样。
 * 总之还需要判断刷新token的时候，过期jwt是否合法的问题。总不能去年的过期token也拿来刷新吧。
 * 而在过期前去刷新token的话，至少不会发生这种事情
 * 不过我这里自己写demo，采用的还是2.2的方式，也就是过期后给个新的，思路如下：
 * 登录后颁发token，token有个时间戳，同时以username拼装作为key，保存这个时间戳到缓存（redis，cache）
 * 请求来了，过滤器解析token，没过期的话，还需要比较缓存中的时间戳和token的时间戳是不是一样 ，如果时间戳不一样，说明该token不能刷新。无视
 * 注销，清除缓存数据
 * 这样就可以避免token过期后，我还能拿到这个token无限制的refresh
 **/