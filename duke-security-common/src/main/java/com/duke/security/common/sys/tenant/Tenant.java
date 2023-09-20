package com.duke.security.common.sys.tenant;

import com.duke.common.base.BaseEntity;
import com.duke.security.common.sys.depart.Depart;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.Date;
import java.util.List;

@NoArgsConstructor
@Data
public class Tenant extends BaseEntity<BigDecimal> {
    private String name;
    private String contact;
    private String phone;
    private String remark;
    private List<Depart> departs;

    @Builder
    public Tenant(BigDecimal id, Date createTime, Date updateTime, String creator, String updator, Boolean deleted, Integer version, BigDecimal tenantId, String name, String contact, String phone, String remark, List<Depart> departs) {
        super(id, createTime, updateTime, creator, updator, deleted, version, tenantId);
        this.name = name;
        this.contact = contact;
        this.phone = phone;
        this.remark = remark;
        this.departs = departs;
    }
}
