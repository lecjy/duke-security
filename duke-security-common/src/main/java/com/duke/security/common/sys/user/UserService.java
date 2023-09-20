package com.duke.security.common.sys.user;

import java.math.BigDecimal;
import java.util.List;

public interface UserService {
    User loadUserByAccount(String account);

    User currentUser();

    List<User> queryUsersByDepartId(BigDecimal departId);

    List<User> queryUsersByRoleId(BigDecimal roleId);

    List<User> queryUsersWithoutDepart();

    User saveOrUpdateUser(User user);

    List<User> fuzzyQuery(String key);

    User queryUserById(BigDecimal id);

    void deleteUserById(BigDecimal id);

    List<User> queryUsersByIds(List<BigDecimal> ids);
}
