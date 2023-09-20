package com.duke.security.common.sys.resource;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
@NoArgsConstructor
public class ResourceGroup {
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    private BigDecimal id;
    private String name;
    private String[] resources;
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    private BigDecimal tenantId;

    @Builder
    public ResourceGroup(BigDecimal id, String name, String[] resources, BigDecimal tenantId) {
        this.id = id;
        this.name = name;
        this.resources = resources;
        this.tenantId = tenantId;
    }
}
