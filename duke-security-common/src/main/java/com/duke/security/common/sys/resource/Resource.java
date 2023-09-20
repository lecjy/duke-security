package com.duke.security.common.sys.resource;

import com.duke.common.base.BaseEntity;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.math.BigDecimal;
import java.util.Date;

@Data
@NoArgsConstructor
public class Resource extends BaseEntity<BigDecimal> implements GrantedAuthority {
    private static final long serialVersionUID = -3118462675959836713L;
    private BigDecimal pid;
    private String name;
    private String pathes;
    private String methodes;
    private String meta;
    private Integer type;
    private Integer sequence;
    private Boolean general;
    private Boolean enabled;
    private String remark;

    @Builder
    public Resource(BigDecimal id, Date createTime, Date updateTime, String creator, String updator, Boolean deleted, Integer version, BigDecimal tenantId, BigDecimal pid, String name, String pathes, String methodes, String meta, Integer type, Integer sequence, Boolean general, Boolean enabled, String remark) {
        super(id, createTime, updateTime, creator, updator, deleted, version, tenantId);
        this.pid = pid;
        this.name = name;
        this.pathes = pathes;
        this.methodes = methodes;
        this.meta = meta;
        this.type = type;
        this.sequence = sequence;
        this.general = general;
        this.enabled = enabled;
        this.remark = remark;
    }

    @Override
    public String getAuthority() {
//        return methodes + ";" + pathes;
        return pathes;
    }
}
