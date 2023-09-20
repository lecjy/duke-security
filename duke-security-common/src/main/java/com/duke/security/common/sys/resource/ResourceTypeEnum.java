package com.duke.security.common.sys.resource;

import lombok.Getter;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Getter
public enum ResourceTypeEnum {
    MENU(1, "菜单"),
    FUNCTION(2, "功能"),
    OPERATION(3, "操作"),
    INITIALIZING(100, "初始化中"),
    ABNORMAL(101, "可删除");

    private Integer key;
    private String value;

    public Integer getKey() {
        return this.key;
    }

    public String getValue() {
        return value;
    }

    ResourceTypeEnum(Integer key, String value) {
        this.key = key;
        this.value = value;
    }

    private static Map<String, String> enumMap = new HashMap<>();

    public static Map<String, String> enumMap() {
        return enumMap;
    }

    public static String getValue(Integer key) {
        if (key == null) {
            return null;
        }
        return enumMap.get(key);
    }

    static {
        Arrays.stream(values()).forEach((item) -> {
            enumMap.put(item.getKey() + "", item.getValue());
        });
    }
}
