package com.springbootsecurity.springbootjwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

    @GetMapping("/panel")
    public ResponseEntity<String> adminPanel() {
        return ResponseEntity.ok("Welcome to the Secured Admin Panel via JWT!");
    }
}