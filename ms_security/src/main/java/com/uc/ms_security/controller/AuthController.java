package com.uc.ms_security.controller;

import com.uc.ms_security.dto.auth.AuthResponseDTO;
import com.uc.ms_security.dto.auth.LoginRequestDTO;
import com.uc.ms_security.dto.auth.LoginResultDTO;
import com.uc.ms_security.dto.auth.RegisterRequestDTO;
import com.uc.ms_security.dto.auth.RegisterResponseDTO;
import com.uc.ms_security.dto.auth.VerifyTwoFactorRequestDTO;
import com.uc.ms_security.service.AuthService;
import com.uc.ms_security.service.TwoFactorCookieService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final TwoFactorCookieService twoFactorCookieService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(
            @Valid @RequestBody LoginRequestDTO dto) {

        LoginResultDTO result = authService.login(dto);

        // Si el usuario no tiene habilitado el 2FA,
        // devuelve directamente el JWT.
        if (result.challengeId() == null) {
            return ResponseEntity.ok(result.response());
        }

        // Si requiere 2FA, establece la cookie temporal y cabecera de desafío.
        HttpHeaders headers = new HttpHeaders();

        twoFactorCookieService.addChallengeCookie(
                headers,
                result
        );

        if (result.challengeId() != null) {
            headers.add("X-2FA-Challenge-Id", result.challengeId());
        }

        return new ResponseEntity<>(
                result.response(),
                headers,
                HttpStatus.ACCEPTED
        );
    }

    @PostMapping("/2fa/verify")
    public ResponseEntity<AuthResponseDTO> verifyTwoFactor(
            HttpServletRequest request,
            @Valid @RequestBody VerifyTwoFactorRequestDTO dto) {

        // Recupera el identificador del desafío desde la cabecera o cookie.
        String challengeId = twoFactorCookieService
                .findChallengeId(request)
                .orElse(null);

        // Verifica el código y genera el JWT definitivo.
        AuthResponseDTO response = authService.verifyTwoFactor(
                challengeId,
                dto
        );

        // Elimina la cookie después de una verificación exitosa.
        HttpHeaders headers = new HttpHeaders();

        twoFactorCookieService.clearChallengeCookie(headers);

        return new ResponseEntity<>(
                response,
                headers,
                HttpStatus.OK
        );
    }

    @PostMapping("/register")
    public RegisterResponseDTO register(
            @Valid @RequestBody RegisterRequestDTO dto) {

        return authService.register(dto);
    }
}
