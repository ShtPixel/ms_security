package com.uc.ms_security.controller;

import com.uc.ms_security.dto.AuthResponseDTO;
import com.uc.ms_security.dto.LoginRequestDTO;
import com.uc.ms_security.dto.RegisterRequestDTO;
import com.uc.ms_security.dto.RegisterResponseDTO;
import com.uc.ms_security.dto.TwoFactorSettingsRequestDTO;
import com.uc.ms_security.dto.TwoFactorVerifyRequestDTO;
import com.uc.ms_security.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<Object> login(
            @Valid @RequestBody LoginRequestDTO dto) {
        Object response = authService.login(dto);
        return response instanceof AuthResponseDTO
                ? ResponseEntity.ok(response)
                : ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    @PostMapping("/2fa/verify")
    public AuthResponseDTO verifyTwoFactor(
            @Valid @RequestBody TwoFactorVerifyRequestDTO dto) {
        return authService.verifyTwoFactor(dto);
    }

    @PutMapping("/2fa")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void updateTwoFactor(
            Authentication authentication,
            @Valid @RequestBody TwoFactorSettingsRequestDTO dto) {
        authService.updateTwoFactor(Long.valueOf(authentication.getName()), dto);
    }

    @PostMapping("/register")
    public RegisterResponseDTO register(
            @Valid @RequestBody RegisterRequestDTO dto) {
        return authService.register(dto);
    }
}
