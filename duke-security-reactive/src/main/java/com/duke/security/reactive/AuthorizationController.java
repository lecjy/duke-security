package com.duke.security.reactive;

import com.duke.common.base.utils.StringUtils;
import com.duke.common.cache.utils.RedisUtils;
import com.duke.security.common.JWTTokenUtils;
import com.duke.security.common.LoginRequest;
import com.duke.security.common.sys.user.User;
import com.duke.security.common.sys.user.UserService;
import com.google.code.kaptcha.Producer;
import io.netty.buffer.UnpooledByteBufAllocator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.buffer.NettyDataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.FastByteArrayOutputStream;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

@RestController
@RequestMapping("/auth")
@Slf4j
public class AuthorizationController {
    @Value("${captcha.cache.preffix:auth.captcha.}")
    private String captchaCachePreffix;
    @Autowired
    private Producer producer;
    @Autowired
    private UserService userService;

    @PostMapping("/login")
    public Mono<Void> login(ServerHttpResponse response, @RequestBody LoginRequest request) {
        String uuid = request.getUuid();
        String captcha = request.getCaptcha();
        if (StringUtils.isEmpty(uuid)) {
            throw new AuthenticationException("验证码uuid不能为空") {
            };
        }
        String cacheCaptcha = (String) RedisUtils.get(captchaCachePreffix + uuid);
        // 一次性验证码，立即删除缓存，防止恶意暴力破解密码
        RedisUtils.delete(captchaCachePreffix + uuid);
        if (StringUtils.isEmpty(cacheCaptcha) || StringUtils.isEmpty(captcha) || !captcha.equalsIgnoreCase(cacheCaptcha)) {
            throw new AuthenticationException("验证码不正确") {
            };
        }
        User user = userService.loadUserByAccount(request.getAccount());
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
        HttpHeaders headers = response.getHeaders();
        try {
            headers.add(HttpHeaders.AUTHORIZATION, JWTTokenUtils.generateToken(user));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            ReactiveResponseUtils.response(response, HttpStatus.INTERNAL_SERVER_ERROR, "登录失败！", false);
        }
        return Mono.empty();
    }

    @GetMapping("/captcha.jpg")
    public Mono<Void> captcha(ServerHttpResponse response, LoginRequest request) {
        String uuid = request.getUuid();
        if (StringUtils.isEmpty(uuid)) {
            throw new AuthenticationException("缺少uuid") {
            };
        }
        response.getHeaders().add("Cache-Control", "no-store, no-cache");
        response.getHeaders().setContentType(MediaType.IMAGE_JPEG);
        String text = producer.createText();
        RedisUtils.set(captchaCachePreffix + uuid, text, 60);
        BufferedImage image = producer.createImage(text);
        FastByteArrayOutputStream os = new FastByteArrayOutputStream();
        // TODO 非阻塞式上下文中使用阻塞式IO可能导致饥饿
        try {
            ImageIO.write(image, "jpg", os);
        } catch (IOException e) {
            e.printStackTrace();
            throw new AuthenticationException("缺少uuid") {
            };
        }
//        return ServerResponse.status(HttpStatus.OK)
//                .contentType(MediaType.IMAGE_JPEG)
//                .body(BodyInserters.fromResource(new ByteArrayResource(os.toByteArray())));
        return response.writeWith(Flux.create(sink -> {
            NettyDataBufferFactory nettyDataBufferFactory = new NettyDataBufferFactory(new UnpooledByteBufAllocator(false));
            sink.next(nettyDataBufferFactory.wrap(os.toByteArray()));
            sink.complete();
        }));
    }
}
