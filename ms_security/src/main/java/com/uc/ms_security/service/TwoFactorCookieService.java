package com.uc.ms_security.service;

import com.uc.ms_security.dto.auth.LoginResultDTO;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;

@Service
public class TwoFactorCookieService {

    private static final String COOKIE_NAME = "twoFactorChallenge";
    private static final String COOKIE_PATH = "/api/auth/2fa/verify";

    @Value("${security.two-factor.cookie-secure:false}")
    private boolean secureCookie;

    public void addChallengeCookie(HttpHeaders headers, LoginResultDTO loginResult) {
        Duration remaining = Duration.between(Instant.now(), loginResult.challengeExpiresAt());
        headers.add(
                HttpHeaders.SET_COOKIE,
                createCookie(loginResult.challengeId(), remaining).toString()
        );
    }

    public Optional<String> findChallengeId(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }

        return Arrays.stream(cookies)
                .filter(cookie -> COOKIE_NAME.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst();
    }

    public void clearChallengeCookie(HttpHeaders headers) {
        headers.add(
                HttpHeaders.SET_COOKIE,
                createCookie("", Duration.ZERO).toString()
        );
    }

    private ResponseCookie createCookie(String value, Duration maxAge) {
        return ResponseCookie.from(COOKIE_NAME, value)
                .httpOnly(true)
                .secure(secureCookie)
                .sameSite("Strict")
                .path(COOKIE_PATH)
                .maxAge(maxAge.isNegative() ? Duration.ZERO : maxAge)
                .build();
    }
}
