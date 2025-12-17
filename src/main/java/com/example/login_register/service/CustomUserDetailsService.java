package com.example.login_register.service;

import com.example.login_register.domain.User;
import com.example.login_register.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // Spring Security dùng khi login thường
    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found"));

        return buildUserDetails(user);
    }

    // ✅ DÙNG CHO JWT (THEO USER ID)
    public UserDetails loadUserById(Long id) {

        User user = userRepository.findById(id)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found"));

        return buildUserDetails(user);
    }

    // ================= HELPER =================
    private UserDetails buildUserDetails(User user) {
        return org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())
                .password(user.getPassword() == null ? "" : user.getPassword())
                .roles(user.getRole()) // USER / ADMIN (KHÔNG ROLE_)
                .build();
    }
}

