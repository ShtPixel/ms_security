package com.uc.ms_security.service;

import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Servicio de recuperación de contraseña por código OTP de 6 dígitos.
 * <p>
 * Flujo:
 * 1. {@link #sendResetCode(String)} – el usuario ingresa su correo → se genera un código de
 *    6 dígitos, se almacena en memoria (con expiración de 10 minutos) y se envía al correo.
 * 2. {@link #verifyCode(String, String)} – el usuario ingresa el código → si es válido se
 *    devuelve un token de un solo uso para autorizar el cambio de contraseña.
 * 3. {@link #resetPassword(String, String)} – el usuario envía el token + nueva contraseña →
 *    se actualiza la contraseña y el token queda invalidado.
 */
@Service
public class PasswordResetService {

    private static final Logger LOGGER = LoggerFactory.getLogger(PasswordResetService.class);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int CODE_VALIDITY_MINUTES = 10;

    // email → pending entry (código hasheado + expiración)
    private final ConcurrentMap<String, PendingReset> pendingByEmail = new ConcurrentHashMap<>();

    // resetToken → email (válido solo después de verificar el código)
    private final ConcurrentMap<String, String> confirmedTokens = new ConcurrentHashMap<>();

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final NotificationService notificationService;

    public PasswordResetService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            NotificationService notificationService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.notificationService = notificationService;
    }

    // ------------------------------------------------------------------ //
    //  Paso 1: solicitar código                                           //
    // ------------------------------------------------------------------ //

    /**
     * Genera un código OTP de 6 dígitos, lo almacena en memoria (bcrypt) y lo envía
     * al correo del usuario.  Por seguridad siempre responde 200 aunque el correo no exista.
     */
    public void sendResetCode(String email) {
        purgeExpired();

        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
        boolean userExists = userRepository.existsByEmail(normalizedEmail);

        if (!userExists) {
            // No revelamos si el correo está registrado o no
            LOGGER.warn("Solicitud de reset para correo no registrado: {}", normalizedEmail);
            return;
        }

        String code = String.format(Locale.ROOT, "%06d", RANDOM.nextInt(1_000_000));
        LocalDateTime expiresAt = LocalDateTime.now(ZoneOffset.UTC)
                .plus(CODE_VALIDITY_MINUTES, ChronoUnit.MINUTES);

        PendingReset entry = new PendingReset(passwordEncoder.encode(code), expiresAt);
        pendingByEmail.put(normalizedEmail, entry);

        LOGGER.info("Código de reset enviado a {} (vence en {} min)", normalizedEmail, CODE_VALIDITY_MINUTES);
        notificationService.sendPasswordResetCode(normalizedEmail, code);
    }

    // ------------------------------------------------------------------ //
    //  Paso 2: verificar código                                           //
    // ------------------------------------------------------------------ //

    /**
     * Verifica el código OTP.  Si es válido devuelve un token de un solo uso
     * que el frontend deberá incluir en la petición de cambio de contraseña.
     *
     * @return resetToken (UUID)
     */
    public String verifyCode(String email, String code) {
        purgeExpired();

        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
        PendingReset entry = pendingByEmail.get(normalizedEmail);

        if (entry == null || !entry.isValid()) {
            throw invalidCode();
        }

        synchronized (entry) {
            // Re-check inside the monitor
            if (!entry.isValid() || !passwordEncoder.matches(code, entry.hashedCode())) {
                throw invalidCode();
            }

            // Consume the OTP immediately (single-use)
            pendingByEmail.remove(normalizedEmail);
        }

        // Emit a short-lived reset token
        String resetToken = UUID.randomUUID().toString();
        LocalDateTime tokenExpiry = LocalDateTime.now(ZoneOffset.UTC)
                .plus(CODE_VALIDITY_MINUTES, ChronoUnit.MINUTES);
        confirmedTokens.put(resetToken, normalizedEmail + "|" + tokenExpiry);

        LOGGER.info("Código de reset verificado para {}", normalizedEmail);
        return resetToken;
    }

    // ------------------------------------------------------------------ //
    //  Paso 3: cambiar contraseña                                         //
    // ------------------------------------------------------------------ //

    /**
     * Cambia la contraseña usando el {@code resetToken} obtenido en el paso 2.
     */
    @Transactional
    public void resetPassword(String resetToken, String newPassword) {
        purgeExpired();

        String payload = confirmedTokens.get(resetToken);
        if (payload == null) {
            throw invalidToken();
        }

        // payload format: "email|expiryDateTime"
        String[] parts = payload.split("\\|", 2);
        if (parts.length != 2) {
            confirmedTokens.remove(resetToken);
            throw invalidToken();
        }

        LocalDateTime expiry = LocalDateTime.parse(parts[1]);
        if (!LocalDateTime.now(ZoneOffset.UTC).isBefore(expiry)) {
            confirmedTokens.remove(resetToken);
            throw invalidToken();
        }

        String email = parts[0];
        User user = userRepository.findByEmail(email)
                .orElseThrow(this::invalidToken);

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Invalidate token
        confirmedTokens.remove(resetToken);

        LOGGER.info("Contraseña restablecida para {}", email);
    }

    // ------------------------------------------------------------------ //
    //  Helpers                                                            //
    // ------------------------------------------------------------------ //

    private void purgeExpired() {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        pendingByEmail.entrySet().removeIf(e -> !e.getValue().isValid(now));
        confirmedTokens.entrySet().removeIf(e -> {
            String[] p = e.getValue().split("\\|", 2);
            if (p.length != 2) return true;
            try {
                return !LocalDateTime.now(ZoneOffset.UTC).isBefore(LocalDateTime.parse(p[1]));
            } catch (Exception ex) {
                return true;
            }
        });
    }

    private ApplicationException invalidCode() {
        return new ApplicationException(
                ErrorCase.UNAUTHORIZED,
                "El código de verificación es incorrecto, expiró o ya fue utilizado"
        );
    }

    private ApplicationException invalidToken() {
        return new ApplicationException(
                ErrorCase.UNAUTHORIZED,
                "El token de recuperación es inválido o ha expirado"
        );
    }

    // ------------------------------------------------------------------ //
    //  Inner record                                                       //
    // ------------------------------------------------------------------ //

    private record PendingReset(String hashedCode, LocalDateTime expiresAt) {
        boolean isValid() {
            return isValid(LocalDateTime.now(ZoneOffset.UTC));
        }

        boolean isValid(LocalDateTime now) {
            return expiresAt.isAfter(now);
        }
    }
}

