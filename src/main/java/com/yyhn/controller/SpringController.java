package com.yyhn.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SpringController {

    @RequestMapping("/hello")
    public Object sayHello(){
        return "hello";
    }
    @RequestMapping("user/hello")
    public Object userSayHello(){
        return "hello user";
    }
    @RequestMapping("/dba/hello")
    public Object dbaSayHello(){
        return "hello dba";
    }
}
