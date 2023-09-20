package com.duke.security.common.sys.resource;

import com.duke.security.common.sys.role.RoleResourceGroup;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Set;

public interface ResourceService {
    List<Resource> queryOperationResources();

    int changeOperationResourcesToInitializing();

    int changeOperationResourcesToOK(List<BigDecimal> resourcesToRecovery);

    int insertResources(List<Resource> resourcesToInsert);

    int changeOperationResourcesToManualAfterInitializing();

    Resource queryResourceById(BigDecimal id);

    List<Resource> queryResources();

    List<Resource> queryResourcesByRoleId(BigDecimal bigDecimal);

    List<Resource> queryResourcesByGroupId(BigDecimal groupId);

    void saveOrUpdateResource(Resource resource);

    void moveResources(BigDecimal pid, List<BigDecimal> ids);

    void deleteResourceById(BigDecimal id);

    void deleteRoleResourceGroupRelationByRoleId(BigDecimal roleId);

    void insertRoleResourceGroupRelations(List<RoleResourceGroup> set);

    void saveOrUpdateResourceGroup(ResourceGroup group);

    List<ResourceGroup> queryResourceGroupsByRoleId(BigDecimal roleId);

    List<ResourceGroup> queryResourceGroupsByRoleIds(Set<BigDecimal> set);

    List<ResourceGroup> queryResourceGroups();

    Map<BigDecimal, List<BigDecimal>> queryResourceGroupIdsMapByRoleId(Set<BigDecimal> collect);

    void deleteResourceGroupById(BigDecimal id);
}
