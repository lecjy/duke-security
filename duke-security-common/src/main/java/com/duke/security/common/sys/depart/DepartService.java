package com.duke.security.common.sys.depart;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

public interface DepartService {
    List<Depart> queryDeparts();

    List<Depart> queryChildren(BigDecimal pid);

    Map<BigDecimal, List<Depart>> queryGrandson(BigDecimal pid);

    Depart saveOrUpdateDepart(Depart depart);

    boolean deleteDepartById(BigDecimal id);

    Depart queryDepartById(BigDecimal id);
}
