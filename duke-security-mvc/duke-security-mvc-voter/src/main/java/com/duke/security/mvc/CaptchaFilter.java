package com.duke.security.mvc;

import com.duke.common.cache.utils.RedisUtils;
import com.google.code.kaptcha.Producer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import javax.imageio.ImageIO;
import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.awt.image.BufferedImage;
import java.io.IOException;

@Component
@WebFilter(filterName = "captchaFilter", urlPatterns = "/auth/captcha.jpg", dispatcherTypes = DispatcherType.REQUEST)
public class CaptchaFilter implements Filter {
    @Value("${captcha.cache.preffix:auth.captcha.}")
    private String captchaCachePreffix;
    @Autowired
    private Producer producer;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        if (!"/auth/captcha.jpg".equals(request.getServletPath())) {
            chain.doFilter(servletRequest, servletResponse);
            return;
        }
        response.setHeader("Cache-Control", "no-store, no-cache");
        response.setContentType(MediaType.IMAGE_JPEG_VALUE);
        // 生成文字验证码
        String text = producer.createText();
        // 保存到 redis,60秒
        RedisUtils.set(captchaCachePreffix + request.getParameter("uuid"), text, 60);
        // 获取图片验证码
        BufferedImage image = producer.createImage(text);
        try (ServletOutputStream out = response.getOutputStream()) {
            ImageIO.write(image, "jpg", out);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return;
    }

    @Override
    public void destroy() {
    }
}