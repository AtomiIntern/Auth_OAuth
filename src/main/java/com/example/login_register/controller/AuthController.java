package com.example.login_register.controller;

import com.example.login_register.config.ApiResponse;
import com.example.login_register.domain.FacebookLoginRequest;
import com.example.login_register.domain.LoginRequest;
import com.example.login_register.domain.User;
import com.example.login_register.service.AuthService;
import com.example.login_register.domain.AuthResponse;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // ================= REGISTER =================
    @PostMapping("/register")
    public ApiResponse<User> register(@RequestBody User user) {

        ApiResponse<User> response = new ApiResponse<>();
        response.setResult(authService.register(user));
        return response;
    }

    // ================= LOGIN =================
    @PostMapping("/login")
    public ApiResponse<AuthResponse> login(
            @RequestBody LoginRequest request) {

        AuthResponse authResponse = authService.login(
                request.getUsername(),
                request.getPassword()
        );

        ApiResponse<AuthResponse> response = new ApiResponse<>();
        response.setResult(new AuthResponse(
                authResponse.getAccessToken(),
                authResponse.getRefreshToken()
        ));

        return response;
    }

    // ================= LOGIN FACEBOOK =================
    @PostMapping("/login/facebook")
    public ApiResponse<AuthResponse> loginWithFacebook(
            @RequestBody FacebookLoginRequest request) {

        AuthResponse authResponse =
                authService.loginWithFacebook(request.getAccessToken());

        ApiResponse<AuthResponse> response = new ApiResponse<>();
        response.setResult(new AuthResponse(
                authResponse.getAccessToken(),
                authResponse.getRefreshToken()
        ));

        return response;
    }
}
