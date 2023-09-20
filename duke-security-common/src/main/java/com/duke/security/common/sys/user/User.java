package com.duke.security.common.sys.user;


import com.duke.common.base.BaseEntity;
import com.duke.security.common.sys.depart.Depart;
import com.duke.security.common.sys.resource.Resource;
import com.duke.security.common.sys.role.Role;
import com.duke.security.common.sys.tenant.Tenant;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

@NoArgsConstructor
@Data
public class User extends BaseEntity<BigDecimal> implements UserDetails {
    private String name;
    private String account;
    private String password;
    private Integer sequence;
    private String phone;
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    private BigDecimal roleId;
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    private BigDecimal departId;
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    private BigDecimal tenantId;

    private Collection<Resource> authorities = new ArrayList<>();

    private Boolean accountNonExpired;
    private Boolean accountNonLocked;
    private Boolean credentialsNonExpired;
    private Boolean enabled;

    private Depart depart;
    private Role role;
    private Tenant tenant;

    @Builder
    public User(BigDecimal id, Date createTime, Date updateTime, String creator, String updator, Boolean deleted, Integer version, BigDecimal tenantId, String name, String account, String password, Integer sequence, String phone, BigDecimal roleId, BigDecimal departId, BigDecimal tenantId1, Collection<Resource> authorities, Boolean accountNonExpired, Boolean accountNonLocked, Boolean credentialsNonExpired, Boolean enabled, Depart depart, Role role, Tenant tenant) {
        super(id, createTime, updateTime, creator, updator, deleted, version, tenantId);
        this.name = name;
        this.account = account;
        this.password = password;
        this.sequence = sequence;
        this.phone = phone;
        this.roleId = roleId;
        this.departId = departId;
        this.tenantId = tenantId1;
        this.authorities = authorities;
        this.accountNonExpired = accountNonExpired;
        this.accountNonLocked = accountNonLocked;
        this.credentialsNonExpired = credentialsNonExpired;
        this.enabled = enabled;
        this.depart = depart;
        this.role = role;
        this.tenant = tenant;
    }

    @Override
    public String getUsername() {
        return account;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }
}
