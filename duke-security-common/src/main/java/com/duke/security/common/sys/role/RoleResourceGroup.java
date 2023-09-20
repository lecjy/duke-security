package com.duke.security.common.sys.role;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RoleResourceGroup {
    private BigDecimal id;
    private BigDecimal roleId;
    private BigDecimal resourceGroupId;
    private BigDecimal tenantId;
}
