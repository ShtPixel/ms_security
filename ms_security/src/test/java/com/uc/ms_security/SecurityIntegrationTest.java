package com.uc.ms_security;

import com.uc.ms_security.entity.User;
import com.uc.ms_security.service.JwtService;
import com.uc.ms_security.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserRepository userRepository;

    @Test
    void loginIsPublicAndReturnsGenericUnauthorizedForInvalidCredentials() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "jwt-integration-missing@invalid.example",
                                  "password": "incorrecta"
                                }
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCase").value("UNAUTHORIZED"))
                .andExpect(jsonPath("$.message").value("Credenciales incorrectas"));
    }

    @Test
    void protectedEndpointsRejectMissingAndInvalidTokens() throws Exception {
        mockMvc.perform(get("/api/users"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer not-a-valid-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedEndpointAcceptsValidBearerToken() throws Exception {
        User user = userRepository.findByEmail("admin@uc.edu.co")
                .orElseThrow();
        String token = jwtService.generateToken(user).accessToken();

        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void protectedEndpointRejectsValidTokenWithoutPermission() throws Exception {
        User user = new User();
        user.setId(Long.MAX_VALUE);
        user.setEmail("sin-permisos@mail.com");
        String token = jwtService.generateToken(user).accessToken();

        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }
}
