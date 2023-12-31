package com.practice.ecom.controller;

import com.practice.ecom.entity.User;
import com.practice.ecom.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.PostConstruct;

@RestController
public class UserController {

    @Autowired
    private UserService userService;

    @PostConstruct
    public void initUsersAndRoles(){
        userService.initRoleAndUser();
    }

    @PostMapping({"/registerNewUser"})
    public User registerNewUser(@RequestBody User user){
        return userService.registerNewUser(user);
    }

    @GetMapping({"/admin"})
    @PreAuthorize("hasRole('Admin')")
    public String forAdmin(){
        return "This endpoint is only accessible to Administrators";
    }

    @GetMapping({"/user"})
    @PreAuthorize("hasRole('User')")
    public String forUser(){
        return "This endpoint is only accessible to standard Users";
    }

}
