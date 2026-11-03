package com.uc.ms_security.controller;

import com.uc.ms_security.dto.auth.AuthResponseDTO;
import com.uc.ms_security.dto.auth.LoginRequestDTO;
import com.uc.ms_security.dto.auth.LoginResultDTO;
import com.uc.ms_security.dto.auth.OAuthExchangeRequestDTO;
import com.uc.ms_security.dto.auth.OAuthStateResponseDTO;
import com.uc.ms_security.dto.auth.RegisterRequestDTO;
import com.uc.ms_security.dto.auth.RegisterResponseDTO;
import com.uc.ms_security.dto.auth.VerifyTwoFactorRequestDTO;
import com.uc.ms_security.service.AuthService;
import com.uc.ms_security.service.OAuthLoginService;
import com.uc.ms_security.service.TwoFactorCookieService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.beans.factory.annotation.Value;
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
    private final OAuthLoginService oAuthLoginService;

    @Value("${security.oauth.cookie-secure:false}")
    private boolean oauthCookieSecure;
    @Value("${security.oauth.cookie-same-site:Lax}")
    private String oauthCookieSameSite;

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
