package com.example.login_register.service;

import com.example.login_register.domain.User;
import com.example.login_register.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public User getUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + id));
    }

    public User createUser(User user) {
        if (userRepository.existsByUsername(user.getUsername())) {
            throw new RuntimeException("Username đã tồn tại");
        }

        if (userRepository.existsByEmail(user.getEmail())) {
            throw new RuntimeException("Email đã tồn tại");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole("USER");

        return userRepository.save(user);
    }

    public User updateUser(Long userId, User user) {
        User curUser = getUserById(userId);

        curUser.setUsername(user.getUsername());
        curUser.setEmail(user.getEmail());

        // Chỉ encode password nếu có truyền password mới
        if (user.getPassword() != null && !user.getPassword().isBlank()) {
            curUser.setPassword(passwordEncoder.encode(user.getPassword()));
        }

        return userRepository.save(curUser);
    }

    public void deleteUser(Long userId) {
        User user = getUserById(userId);
        userRepository.delete(user);
    }
}

