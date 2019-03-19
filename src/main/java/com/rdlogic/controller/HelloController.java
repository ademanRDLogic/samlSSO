package com.rdlogic.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HelloController {

    @RequestMapping("/test/authSuccess")
    public String success(){
        return "authSuccess";
    }


    @RequestMapping({"/","/test"})
    public String loginRedirect(){
        return "redirect:/test/authSuccess";
    }

}
