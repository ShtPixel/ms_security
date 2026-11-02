package com.uc.ms_security.service;

import com.uc.ms_security.entity.Session;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
@RequiredArgsConstructor
public class TwoFactorAuthenticationService {

    private static final String TWO_FACTOR_EMAIL = "santiago.quintero50836@ucaldas.edu.co";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int CODE_VALIDITY_MINUTES = 5;

    private final PasswordEncoder passwordEncoder;
    private final NotificationService notificationService;
    private final ConcurrentMap<String, Session> pendingSessions = new ConcurrentHashMap<>();

    public Session sendCode(User user) {
        String code = String.format(Locale.ROOT, "%06d", RANDOM.nextInt(1_000_000));
        LocalDateTime expiresAt = LocalDateTime.now(ZoneOffset.UTC)
                .plus(CODE_VALIDITY_MINUTES, ChronoUnit.MINUTES);

        Session session = new Session();
        session.setToken(UUID.randomUUID().toString());
        session.setCode2FA(passwordEncoder.encode(code));
        session.setExpiration(expiresAt);
        session.setAuthenticated(false);
        session.setUser(user);

        notificationService.sendTwoFactorCode(TWO_FACTOR_EMAIL, code);

        pendingSessions.entrySet().removeIf(
                entry -> !entry.getValue().getExpiration().isAfter(LocalDateTime.now(ZoneOffset.UTC))
        );
        pendingSessions.put(session.getToken(), session);
        return session;
    }

    public Session verifyCode(String challengeId, String code) {
        if (challengeId == null || challengeId.isBlank()) {
            throw invalidTwoFactorCode();
        }

        Session session = pendingSessions.get(challengeId);
        if (session == null) {
            throw invalidTwoFactorCode();
        }

        synchronized (session) {
            if (pendingSessions.get(challengeId) != session
                    || !session.getExpiration().isAfter(LocalDateTime.now(ZoneOffset.UTC))
                    || session.getCode2FA() == null) {
                pendingSessions.remove(challengeId, session);
                throw invalidTwoFactorCode();
            }

            if (!passwordEncoder.matches(code, session.getCode2FA())) {
                throw invalidTwoFactorCode();
            }

            if (!pendingSessions.remove(challengeId, session)) {
                throw invalidTwoFactorCode();
            }

            session.setAuthenticated(true);
            return session;
        }
    }

    private ApplicationException invalidTwoFactorCode() {
        return new ApplicationException(
                ErrorCase.UNAUTHORIZED,
                "El código de verificación es incorrecto, expiró o ya fue utilizado"
        );
    }
}
