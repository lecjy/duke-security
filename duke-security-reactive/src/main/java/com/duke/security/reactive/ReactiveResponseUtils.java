package com.duke.security.reactive;

import com.duke.common.base.Result;
import com.duke.common.base.utils.JacksonUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

public class ReactiveResponseUtils {
    private ReactiveResponseUtils() {
        throw new UnsupportedOperationException("Unsupported Operation");
    }

    public static Mono<Void> response(ServerHttpResponse response, HttpStatus status, String message, boolean success) {
        // spring 5.2之后不需要指定utf-8，默认就是utf-8
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON.getType());
        response.setStatusCode(status);
        // response.sendError(HttpStatus.UNAUTHORIZED.value());//优先级最高会导致前端只能收到401，收不到数据
        // 如果想让浏览器能访问到其他响应头，需要设置 Access-Control-Expose-Headers
        response.getHeaders().add(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, "message");
        response.getHeaders().add("message", message);
        return response(response, Result.builder().code(status.value()).success(success).message(message).build());
    }

    public static Mono<Void> unauthorizedResponse(ServerHttpResponse response, String message) {
        return response(response, HttpStatus.UNAUTHORIZED, message, false);
    }

    public static <T> Mono<Void> okResponse(ServerHttpResponse response, T data) {
        // spring 5.2之后不需要指定utf-8，默认就是utf-8
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON.getType());
        response.setRawStatusCode(HttpStatus.OK.value());
        return response(response, Result.success(data));
    }

    public static Mono<Void> okResponse(ServerHttpResponse response) {
        // spring 5.2之后不需要指定utf-8，默认就是utf-8
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON.getType());
        response.setRawStatusCode(HttpStatus.OK.value());
        return response(response, Result.success());
    }

    public static <T> Mono<Void> response(ServerHttpResponse response, Result<T> result) {
        DataBuffer dataBuffer = null;
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            dataBuffer = response.bufferFactory().wrap(objectMapper.writeValueAsBytes(JacksonUtils.toJSONString(result).getBytes(StandardCharsets.UTF_8)));
        } catch (JsonProcessingException jsonProcessingException) {
            jsonProcessingException.printStackTrace();
        }
        return response.writeWith(Mono.just(dataBuffer));
    }
}
