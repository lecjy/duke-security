package com.duke.security.mvc;

import com.duke.common.base.utils.StringUtils;
import com.duke.common.cache.utils.RedisUtils;
import com.duke.security.common.LoginRequest;
import com.google.code.kaptcha.Producer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.awt.image.BufferedImage;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Value("${captcha.cache.preffix:auth.captcha.}")
    private String captchaCachePreffix;
    @Autowired
    private Producer producer;

    // 从这里获取验证码会经过一系列的filter，有性能损失，可以使用filter处理验证码请求，将获取验证码的filter放在filter链的首端
    @GetMapping("/captcha.jpg")
    public void captcha(HttpServletResponse response, LoginRequest request) {
        String uuid = request.getUuid();
        if (StringUtils.isEmpty(uuid)) {
            throw new AuthenticationException("缺少uuid") {
            };
        }
        response.addHeader("Cache-Control", "no-store, no-cache");
        response.setContentType(MediaType.IMAGE_JPEG_VALUE);
        // 生成文字验证码
        String text = producer.createText();
        // 保存到 redis,60秒
        RedisUtils.set(captchaCachePreffix + uuid, text, 60);
        // 获取图片验证码
        BufferedImage image = producer.createImage(text);
        try (ServletOutputStream out = response.getOutputStream()) {
            ImageIO.write(image, "jpg", out);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
