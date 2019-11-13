package com.codegym.inote.configuration;

import com.codegym.inote.model.User;
import com.codegym.inote.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class WebSecurity {

    @Autowired
    private UserRepository userRepository;

    public boolean checkUserId(Authentication authentication, String id) {
        String name = authentication.getName();
        User result = userRepository.findByUsername(name);
        return result != null && result.getId().toString().equals(id);
    }
}
