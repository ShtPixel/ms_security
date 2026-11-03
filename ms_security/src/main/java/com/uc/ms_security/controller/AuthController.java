package com.uc.ms_security.controller;

import com.uc.ms_security.dto.auth.AuthResponseDTO;
import com.uc.ms_security.dto.auth.ForgotPasswordRequestDTO;
import com.uc.ms_security.dto.auth.LoginRequestDTO;
import com.uc.ms_security.dto.auth.LoginResultDTO;
import com.uc.ms_security.dto.auth.OAuthExchangeRequestDTO;
import com.uc.ms_security.dto.auth.OAuthStateResponseDTO;
import com.uc.ms_security.dto.auth.RegisterRequestDTO;
import com.uc.ms_security.dto.auth.RegisterResponseDTO;
import com.uc.ms_security.dto.auth.ResetPasswordRequestDTO;
import com.uc.ms_security.dto.auth.VerifyResetCodeRequestDTO;
import com.uc.ms_security.dto.auth.VerifyTwoFactorRequestDTO;
import com.uc.ms_security.service.AuthService;
import com.uc.ms_security.service.OAuthLoginService;
import com.uc.ms_security.service.PasswordResetService;
import com.uc.ms_security.service.TwoFactorCookieService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.ResponseCookie;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final TwoFactorCookieService twoFactorCookieService;
    private final OAuthLoginService oAuthLoginService;
    private final PasswordResetService passwordResetService;

    @Value("${security.oauth.cookie-secure:false}")
    private boolean oauthCookieSecure;
    @Value("${security.oauth.cookie-same-site:Lax}")
    private String oauthCookieSameSite;

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(
            @Valid @RequestBody LoginRequestDTO dto) {

        LoginResultDTO result = authService.login(dto);

        if (result.challengeId() == null) {
            return ResponseEntity.ok(result.response());
        }

        HttpHeaders headers = new HttpHeaders();
        twoFactorCookieService.addChallengeCookie(headers, result);

        if (result.challengeId() != null) {
            headers.add("X-2FA-Challenge-Id", result.challengeId());
        }

        return new ResponseEntity<>(result.response(), headers, HttpStatus.ACCEPTED);
    }

    @PostMapping("/2fa/verify")
    public ResponseEntity<AuthResponseDTO> verifyTwoFactor(
            HttpServletRequest request,
            @Valid @RequestBody VerifyTwoFactorRequestDTO dto) {

        String challengeId = twoFactorCookieService
                .findChallengeId(request)
                .orElse(null);

        AuthResponseDTO response = authService.verifyTwoFactor(challengeId, dto);

        HttpHeaders headers = new HttpHeaders();
        twoFactorCookieService.clearChallengeCookie(headers);

        return new ResponseEntity<>(response, headers, HttpStatus.OK);
    }

    @PostMapping("/register")
    public RegisterResponseDTO register(
            @Valid @RequestBody RegisterRequestDTO dto) {

        return authService.register(dto);
    }

    // ------------------------------------------------------------------ //
    //  Recuperación de contraseña                                         //
    // ------------------------------------------------------------------ //

    /**
     * Paso 1: el usuario solicita el código OTP enviando su correo.
     * Siempre responde 200 para no revelar si el correo existe o no.
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequestDTO dto) {

        passwordResetService.sendResetCode(dto.email());
        return ResponseEntity.ok(Map.of(
                "message", "Si el correo está registrado recibirás un código de recuperación."
        ));
    }

    /**
     * Paso 2: el usuario verifica el código OTP.
     * Devuelve un {@code resetToken} de un solo uso para autorizar el cambio de contraseña.
     */
    @PostMapping("/reset-password/verify")
    public ResponseEntity<Map<String, String>> verifyResetCode(
            @Valid @RequestBody VerifyResetCodeRequestDTO dto) {

        String resetToken = passwordResetService.verifyCode(dto.email(), dto.code());
        return ResponseEntity.ok(Map.of("resetToken", resetToken));
    }

    /**
     * Paso 3: el usuario cambia su contraseña usando el {@code resetToken}.
     */
    @PostMapping("/reset-password/confirm")
    public ResponseEntity<Map<String, String>> confirmResetPassword(
            @Valid @RequestBody ResetPasswordRequestDTO dto) {

        passwordResetService.resetPassword(dto.resetToken(), dto.newPassword());
        return ResponseEntity.ok(Map.of(
                "message", "Contraseña actualizada exitosamente. Ya puedes iniciar sesión."
        ));
    }

    // ------------------------------------------------------------------ //
    //  OAuth                                                              //
    // ------------------------------------------------------------------ //

    @PostMapping("/oauth/{provider}/state")
    public ResponseEntity<OAuthStateResponseDTO> createOAuthState(
            @org.springframework.web.bind.annotation.PathVariable String provider) {
        String state = oAuthLoginService.createState(provider);
        ResponseCookie cookie = oauthStateCookie(provider, state, 300);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new OAuthStateResponseDTO(state));
    }

    @PostMapping("/oauth/{provider}")
    public ResponseEntity<AuthResponseDTO> exchangeOAuthCode(
            @org.springframework.web.bind.annotation.PathVariable String provider,
            @Valid @RequestBody OAuthExchangeRequestDTO dto,
            HttpServletRequest request) {
        String stateCookie = findOAuthStateCookie(request, provider);
        AuthResponseDTO response = oAuthLoginService.exchange(
                provider, dto.code(), dto.redirectUri(), dto.codeVerifier(), dto.state(), stateCookie);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, oauthStateCookie(provider, "", 0).toString())
                .body(response);
    }

    private ResponseCookie oauthStateCookie(String provider, String value, long maxAgeSeconds) {
        return ResponseCookie.from("oauth_state_" + provider.toLowerCase(java.util.Locale.ROOT), value)
                .httpOnly(true)
                .secure(oauthCookieSecure)
                .sameSite(oauthCookieSameSite)
                .path("/api/auth/oauth")
                .maxAge(java.time.Duration.ofSeconds(maxAgeSeconds))
                .build();
    }

    private String findOAuthStateCookie(HttpServletRequest request, String provider) {
        jakarta.servlet.http.Cookie[] cookies = request.getCookies();
        String expectedName = "oauth_state_" + provider.toLowerCase(java.util.Locale.ROOT);
        if (cookies != null) {
            for (jakarta.servlet.http.Cookie cookie : cookies) {
                if (expectedName.equals(cookie.getName())) return cookie.getValue();
            }
        }
        return null;
    }
}
