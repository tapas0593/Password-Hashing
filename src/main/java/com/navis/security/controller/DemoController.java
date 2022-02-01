package com.navis.security.controller;

import com.navis.security.service.IPasswordEncypt;
import com.navis.security.model.TestObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @Autowired
    private IPasswordEncypt passwordEncyptService;

    @GetMapping("getTestObj")
    public TestObject getTestObject() {
        return passwordEncyptService.getTestObjectUsingRest();
    }
}
