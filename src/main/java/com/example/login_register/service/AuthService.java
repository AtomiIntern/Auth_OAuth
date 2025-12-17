package com.example.login_register.service;

import com.example.login_register.config.JwtUtil;
import com.example.login_register.domain.AuthResponse;
import com.example.login_register.domain.FacebookUser;
import com.example.login_register.domain.User;
import com.example.login_register.domain.Role;
import com.example.login_register.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    // ================= LOGIN THƯỜNG =================
    public AuthResponse login(String username, String password) {

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User không tồn tại"));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Sai mật khẩu");
        }

        UserDetails userDetails = buildUserDetails(user);

        return new AuthResponse(
                jwtUtil.generateAccessToken(userDetails),
                jwtUtil.generateRefreshToken(userDetails)
        );
    }

    // ================= REGISTER =================
    public User register(User user) {

        if (userRepository.existsByEmail(user.getEmail())) {
            throw new RuntimeException("Email đã tồn tại");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole(Role.USER.name()); // USER
        user.setProvider("LOCAL");

        return userRepository.save(user);
    }

    // ================= LOGIN FACEBOOK =================
    public AuthResponse loginWithFacebook(String fbAccessToken) {

        RestTemplate restTemplate = new RestTemplate();

        String url = "https://graph.facebook.com/me" +
                "?fields=id,name,email" +
                "&access_token=" + fbAccessToken;

        FacebookUser fbUser =
                restTemplate.getForObject(url, FacebookUser.class);

        if (fbUser == null || fbUser.getId() == null) {
            throw new RuntimeException("Facebook token không hợp lệ");
        }

        User user = userRepository
                .findByProviderAndProviderId("FACEBOOK", fbUser.getId())
                .orElseGet(() -> {

                    User newUser = new User();
                    newUser.setUsername(fbUser.getName());
                    newUser.setEmail(fbUser.getEmail());
                    newUser.setProvider("FACEBOOK");
                    newUser.setProviderId(fbUser.getId());
                    newUser.setRole(Role.USER.name());

                    return userRepository.save(newUser);
                });

        UserDetails userDetails = buildUserDetails(user);

        return new AuthResponse(
                jwtUtil.generateAccessToken(userDetails),
                jwtUtil.generateRefreshToken(userDetails)
        );
    }

    // ================= LOGIN GOOGLE =================
    public AuthResponse loginWithGoogle(String googleId, String email, String name) {

        User user = userRepository
                .findByProviderAndProviderId("GOOGLE", googleId)
                .orElseGet(() -> {

                    User newUser = new User();
                    newUser.setUsername(name);
                    newUser.setEmail(email);
                    newUser.setProvider("GOOGLE");
                    newUser.setProviderId(googleId);
                    newUser.setRole(Role.USER.name());

                    return userRepository.save(newUser);
                });

        UserDetails userDetails = buildUserDetails(user);

        return new AuthResponse(
                jwtUtil.generateAccessToken(userDetails),
                jwtUtil.generateRefreshToken(userDetails)
        );
    }


    // ================= HELPER =================
    private UserDetails buildUserDetails(User user) {

        return org.springframework.security.core.userdetails.User
                // 🔥 QUAN TRỌNG: username = userId
                .withUsername(String.valueOf(user.getId()))
                .password(user.getPassword() == null ? "" : user.getPassword())
                .authorities("ROLE_" + user.getRole()) // Spring tự hiểu ROLE_
                .build();
    }
}



