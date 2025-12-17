package com.example.login_register.config;

import com.example.login_register.domain.AuthResponse;
import com.example.login_register.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final AuthService authService;

    public OAuth2SuccessHandler(AuthService authService) {
        this.authService = authService;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String googleId = oAuth2User.getAttribute("sub");
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        AuthResponse authResponse =
                authService.loginWithGoogle(googleId, email, name);

        response.setContentType("application/json");
        response.getWriter().write("""
            {
              "accessToken": "%s",
              "refreshToken": "%s"
            }
        """.formatted(
                authResponse.getAccessToken(),
                authResponse.getRefreshToken()
        ));
    }
}
