package com.duke.security.common.sys.tenant;

import java.math.BigDecimal;

public interface TenantService {
    Tenant queryTenantById(BigDecimal tenantId);
}
