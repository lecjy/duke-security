package com.duke.security.common;

import com.duke.security.common.sys.user.User;
import org.springframework.security.core.context.SecurityContextHolder;

import java.math.BigDecimal;

import static net.sf.jsqlparser.util.validation.metadata.NamedObject.user;

public class SecurityContextUtils {

    public static User user() {
        return (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    public static BigDecimal userId() {
        return user().getId();
    }

    public static BigDecimal tenantId() {
        return user().getTenantId();
    }

    public static BigDecimal departId() {
        return user().getDepartId();
    }

    public static BigDecimal roleId() {
        return user().getRoleId();
    }
}
