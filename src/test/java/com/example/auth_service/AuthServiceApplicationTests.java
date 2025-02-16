package com.example.auth_service;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test") // Use a test profile to avoid loading full security
class AuthServiceApplicationTests {

    @Test
    void contextLoads() {
        // Basic test to check if context loads successfully
    }
}
