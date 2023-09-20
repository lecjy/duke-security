package com.duke.security.common.sys;

import lombok.Getter;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Getter
public enum PositionTypeEnum {
    CHIEF(1, "正职"),
    DEPUTY(2, "副职"),
    part_time(3, "兼职");

    private Integer key;
    private String value;

    public Integer getKey() {
        return this.key;
    }

    public String getValue() {
        return value;
    }

    PositionTypeEnum(Integer key, String value) {
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
