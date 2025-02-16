package com.example.auth_service.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service  // ✅ This marks it as a Spring Bean
public class CustomUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // For testing, return a hardcoded user
        return org.springframework.security.core.userdetails.User
                .withUsername(username)
                .password("{noop}password") // `{noop}` means no password encoding
                .roles("USER")
                .build();
    }
}
