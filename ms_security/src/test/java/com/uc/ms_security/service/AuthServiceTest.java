package com.uc.ms_security.service;

import com.uc.ms_security.dto.AuthResponseDTO;
import com.uc.ms_security.dto.LoginRequestDTO;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthService authService;

    @Test
    void loginReturnsTokenWhenCredentialsAreValid() {
        LoginRequestDTO dto = loginRequest("ana@mail.com", "ClaveSegura123!");
        User user = new User();
        user.setPassword("$2a$12$encoded");
        AuthResponseDTO token = new AuthResponseDTO(
                "signed-token",
                "Bearer",
                Instant.now().plusSeconds(900)
        );

        when(userRepository.findByEmail(dto.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(dto.getPassword(), user.getPassword())).thenReturn(true);
        when(jwtService.generateToken(user)).thenReturn(token);

        assertSame(token, authService.login(dto));
        verify(jwtService).generateToken(user);
    }

    @Test
    void loginUsesSameUnauthorizedErrorForUnknownEmailAndWrongPassword() {
        LoginRequestDTO dto = loginRequest("missing@mail.com", "wrong");
        when(userRepository.findByEmail(dto.getEmail())).thenReturn(Optional.empty());

        ApplicationException exception = assertThrows(
                ApplicationException.class,
                () -> authService.login(dto)
        );

        assertEquals(ErrorCase.UNAUTHORIZED, exception.getErrorCase());
        assertEquals("Credenciales incorrectas", exception.getMessage());
        verifyNoInteractions(passwordEncoder, jwtService);
    }

    @Test
    void loginRejectsWrongPasswordWithoutGeneratingToken() {
        LoginRequestDTO dto = loginRequest("ana@mail.com", "wrong");
        User user = new User();
        user.setPassword("$2a$12$encoded");

        when(userRepository.findByEmail(dto.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(dto.getPassword(), user.getPassword())).thenReturn(false);

        ApplicationException exception = assertThrows(
                ApplicationException.class,
                () -> authService.login(dto)
        );

        assertEquals(ErrorCase.UNAUTHORIZED, exception.getErrorCase());
        verifyNoInteractions(jwtService);
    }

    private LoginRequestDTO loginRequest(String email, String password) {
        LoginRequestDTO dto = new LoginRequestDTO();
        dto.setEmail(email);
        dto.setPassword(password);
        return dto;
    }
}
