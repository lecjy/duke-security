package com.duke.security.mvc;

import com.duke.common.base.utils.StringUtils;
import com.duke.common.cache.utils.RedisUtils;
import com.duke.security.common.LoginRequest;
import com.duke.security.common.sys.user.User;
import com.duke.security.common.sys.user.UserService;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Objects;

/**
 * JWTAuthenticationFilter继承于UsernamePasswordAuthenticationFilter，该拦截器用于获取用户登录的信息，只需创建一个token并调用authenticationManager.authenticate()让spring-security去进行验证就可以了，不用自己查数据库再对比密码了，这一步交给spring去操作
 */
public class JWTPasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    @Value("${captcha.cache.preffix:auth.captcha.}")
    private String captchaCachePreffix;

    private ThreadLocal<Boolean> rememberME = new ThreadLocal<>();

    @Autowired
    private UserService userService;

    public JWTPasswordAuthenticationFilter() {
        super(new AntPathRequestMatcher("/auth/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        LoginRequest loginRequest = new LoginRequest();
        try {
            // 从表单中获取用户信息
            if (MediaType.APPLICATION_FORM_URLENCODED_VALUE.equals(request.getContentType())) {
                String username = request.getParameter("username");
                String password = request.getParameter("password");
                String rememberME = request.getParameter("rememberME");
                loginRequest.setAccount(username);
                loginRequest.setPassword(password);
                loginRequest.setRememberME(StringUtils.isNotEmpty(rememberME) && Boolean.parseBoolean(rememberME));
            } else {
                // 从输入流中获取用户信息
                InputStream inputStream = request.getInputStream();
                ObjectMapper objectMapper = new ObjectMapper();
                objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
                loginRequest = objectMapper.readValue(inputStream, LoginRequest.class);
            }
            String uuid = loginRequest.getUuid();
            if (StringUtils.isEmpty(uuid)) {
                throw new AuthenticationException("验证码uuid不能为空") {
                };
            }
            String cacheCaptcha = (String) RedisUtils.get(captchaCachePreffix + uuid);
            // 一次性验证码，立即删除缓存，防止恶意暴力破解密码
            RedisUtils.delete(captchaCachePreffix + uuid);
            String captcha = loginRequest.getCaptcha();
            if (StringUtils.isEmpty(cacheCaptcha) || StringUtils.isEmpty(captcha) || !captcha.equalsIgnoreCase(cacheCaptcha)) {
                throw new AuthenticationException("验证码不正确") {
                };
            }
            rememberME.set(loginRequest.getRememberME());
            if (StringUtils.isEmpty(cacheCaptcha) || StringUtils.isEmpty(captcha) || !captcha.equalsIgnoreCase(cacheCaptcha)) {
                throw new AuthenticationException("验证码不正确") {
                };
            }
            User user = userService.loadUserByAccount(loginRequest.getAccount());
            if (Objects.isNull(user)) {
                throw new UsernameNotFoundException("用户不存在");
            }
            if (!Boolean.TRUE.equals(user.getEnabled())) {
                throw new DisabledException("账户已禁用");
            }
            if (!Boolean.TRUE.equals(user.getAccountNonExpired())) {
                throw new AccountExpiredException("账户已过期");
            }
            if (!Boolean.TRUE.equals(user.getAccountNonLocked())) {
                throw new LockedException("账户已锁定");
            }
            if (!Boolean.TRUE.equals(user.getCredentialsNonExpired())) {
                throw new CredentialsExpiredException("凭证已过期");
            }
            // TODO 检查密码是否正确
//            String passwordSalt = Md5Utils.encodeWithSalt(password, CommonConsts.SALT);
//            if (!Objects.equals(sysUser.getPassword(), passwordSalt)) {
//                HttpResponseUtils.unauthorizedResponse(response, "密码不正确");
//            }
            return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(user, user.getId(), Collections.emptyList()));
        } catch (IOException e) {
            e.printStackTrace();
            throw new AuthenticationException("登录出错") {
            };
        }
    }

    protected void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }

    @Override
    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        super.setAuthenticationManager(authenticationManager);
    }
}