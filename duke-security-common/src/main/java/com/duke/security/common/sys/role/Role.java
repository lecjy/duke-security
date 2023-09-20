package com.duke.security.common.sys.role;

import com.duke.common.base.BaseEntity;
import com.duke.security.common.sys.user.User;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.Date;
import java.util.List;

@Data
@NoArgsConstructor
public class Role extends BaseEntity<BigDecimal> {
    private String name;
    private Integer type;
    private String remark;
    private Boolean enabled;

    private BigDecimal tenantId;
    private List<User> users;
    private List<String> dataPermissions;
    private List<BigDecimal> resourceGroups;

    @Builder
    public Role(BigDecimal id, Date createTime, Date updateTime, String creator, String updator, Boolean deleted, Integer version, BigDecimal tenantId, String name, Integer type, String remark, Boolean enabled, BigDecimal tenantId1, List<User> users, List<String> dataPermissions, List<BigDecimal> resourceGroups) {
        super(id, createTime, updateTime, creator, updator, deleted, version, tenantId);
        this.name = name;
        this.type = type;
        this.remark = remark;
        this.enabled = enabled;
        this.tenantId = tenantId1;
        this.users = users;
        this.dataPermissions = dataPermissions;
        this.resourceGroups = resourceGroups;
    }
}
