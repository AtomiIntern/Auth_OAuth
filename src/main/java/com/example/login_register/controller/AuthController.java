package com.example.login_register.controller;

import com.example.login_register.config.ApiResponse;
import com.example.login_register.domain.FacebookLoginRequest;
import com.example.login_register.domain.LoginRequest;
import com.example.login_register.domain.LoginResponse;
import com.example.login_register.domain.User;
import com.example.login_register.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ApiResponse<User> register(@RequestBody User user) {
        ApiResponse<User> response = new ApiResponse<>();
        response.setResult(this.authService.register(user));
        return response;
    }

    @PostMapping("/login")
    public ApiResponse<LoginResponse> login(@RequestBody LoginRequest request) {

        String token = authService.login(
                request.getUsername(),
                request.getPassword()
        );

        ApiResponse<LoginResponse> response = new ApiResponse<>();
        response.setResult(new LoginResponse(token));

        return response;
    }

    @PostMapping("/login/facebook")
    public ApiResponse<LoginResponse> loginWithFacebook(
            @RequestBody FacebookLoginRequest request) {

        String token = authService.loginWithFacebook(request.getAccessToken());

        ApiResponse<LoginResponse> response = new ApiResponse<>();
        response.setResult(new LoginResponse(token));
        return response;
    }

}


