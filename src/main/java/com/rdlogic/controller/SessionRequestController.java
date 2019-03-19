package com.rdlogic.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@Controller
public class SessionRequestController {

    @RequestMapping("/{client}/getSessionCredentials")
    @ResponseBody
    public ResponseEntity<String> getSessionCredentials(HttpServletRequest request, HttpSession session) {
        return null;
    }
}
