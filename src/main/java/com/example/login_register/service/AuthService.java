package com.example.login_register.service;

import com.example.login_register.config.JwtUtil;
import com.example.login_register.domain.FacebookUser;
import com.example.login_register.domain.User;
import com.example.login_register.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Optional;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    public String login(String username, String password) {

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User không tồn tại"));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Sai mật khẩu");
        }

        return jwtUtil.generateToken(username , user.getRole());
    }

    public User register(User user) {
        if (userRepository.existsByEmail(user.getEmail())) {
            throw new RuntimeException("Email đã tồn tại");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole("ROLE_USER");
        return userRepository.save(user);
    }

    public String loginWithFacebook(String fbAccessToken) {

        //Gọi Facebook API verify token
        RestTemplate restTemplate = new RestTemplate();

        String url = "https://graph.facebook.com/me" +
                "?fields=id,name,email" +
                "&access_token=" + fbAccessToken;

        FacebookUser fbUser = restTemplate.getForObject(url, FacebookUser.class);

        if (fbUser == null || fbUser.getId() == null) {
            throw new RuntimeException("Facebook token không hợp lệ");
        }

        //Tìm user theo providerId
        User user = userRepository
                .findByProviderAndProviderId("FACEBOOK", fbUser.getId())
                .orElseGet(() -> {

                    //Chưa tồn tại → tạo mới
                    User newUser = new User();
                    newUser.setUsername(fbUser.getName());
                    newUser.setEmail(fbUser.getEmail());
                    newUser.setProvider("FACEBOOK");
                    newUser.setProviderId(fbUser.getId());
                    newUser.setRole("ROLE_USER");

                    return userRepository.save(newUser);
                });

        //Sinh JWT của bạn
        return jwtUtil.generateToken(user.getUsername(), user.getRole());
    }

}

