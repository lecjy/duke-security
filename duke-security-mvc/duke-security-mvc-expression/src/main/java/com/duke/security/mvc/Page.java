package com.duke.security.mvc;

import lombok.Data;

import java.util.List;

@Data
public class Page<E> {
    private long totalRecord;
    private long totalPage;
    private List<E> data;
}
