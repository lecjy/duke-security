package com.duke.security.common.sys.role;

import java.math.BigDecimal;
import java.util.List;

public interface RoleService {

    Role saveOrUpdateRole(Role role);

    List<Role> queryRoles();

    Role queryRoleById(BigDecimal id);

    boolean deleteRoleById(BigDecimal id);
}
