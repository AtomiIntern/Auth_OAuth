package com.example.login_register.controller;

import com.example.login_register.config.ApiResponse;
import com.example.login_register.domain.User;
import com.example.login_register.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserService userService;


    @PostMapping("/add")
    public ApiResponse<User> createUser(@RequestBody User user) {
        ApiResponse<User> response = new ApiResponse<>();
        response.setResult(userService.createUser(user));
        return response;
    }


    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping
    public ApiResponse<List<User>> getAllUsers() {
        ApiResponse<List<User>> response = new ApiResponse<>();
        response.setResult(userService.getAllUsers());
        return response;
    }


    @GetMapping("/{id}")
    public ApiResponse<User> getUserById(@PathVariable Long id) {
        ApiResponse<User> response = new ApiResponse<>();
        response.setResult(userService.getUserById(id));
        return response;
    }


    @PutMapping("/{id}")
    public ApiResponse<User> updateUser(
            @PathVariable Long id,
            @RequestBody User user) {

        ApiResponse<User> response = new ApiResponse<>();
        response.setResult(userService.updateUser(id, user));
        return response;
    }


    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public ApiResponse<String> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);

        ApiResponse<String> response = new ApiResponse<>();
        response.setResult("Xóa user thành công");
        return response;
    }
}

