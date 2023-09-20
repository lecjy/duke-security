package com.duke.security.common.sys.depart;

import com.duke.common.base.BaseEntity;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Length;

import javax.validation.constraints.NotEmpty;
import java.math.BigDecimal;
import java.util.Date;

@Data
@NoArgsConstructor
public class Depart extends BaseEntity<BigDecimal> {
    @NotEmpty
    @Length(min = 2, max = 50)
    private String name;
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    private BigDecimal pid;
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    private BigDecimal leaderId;
    private Integer sequence;
    private String remark;
    private String leaderName;

    @Builder
    public Depart(BigDecimal id, Date createTime, Date updateTime, String creator, String updator, Boolean deleted, Integer version, BigDecimal tenantId, String name, BigDecimal pid, BigDecimal leaderId, Integer sequence, String remark, String leaderName) {
        super(id, createTime, updateTime, creator, updator, deleted, version, tenantId);
        this.name = name;
        this.pid = pid;
        this.leaderId = leaderId;
        this.sequence = sequence;
        this.remark = remark;
        this.leaderName = leaderName;
    }
}
