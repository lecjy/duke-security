package com.duke.security.common;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {
    private String account;
    private String password;
    private String captcha;
    private String uuid;
    private Boolean rememberME;
}
