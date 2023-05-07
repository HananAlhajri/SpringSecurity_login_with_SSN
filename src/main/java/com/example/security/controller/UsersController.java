package com.example.security.controller;

import com.example.security.entity.Role;
import com.example.security.entity.User;
import com.example.security.service.implementations.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/v1/manage-users")
@RequiredArgsConstructor
public class UsersController {

    private final UserService userService;

    @GetMapping("/users")
    public String helloUser(){
        return "Hello from secured End Point for USERS only";
    }

    @GetMapping("/admin")
    public String helloAdmin(){
        return "Hello from secured End Point for ADMIN only";
    }

    @GetMapping("/all")
    public ResponseEntity<List<User>> getAllUsers(){
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @PostMapping("/assign")
    public ResponseEntity<User> assignUserRole(@RequestBody Integer userId, @RequestBody Role role){
        return ResponseEntity.ok(userService.assignUserRole(userId, role));
    }
}
