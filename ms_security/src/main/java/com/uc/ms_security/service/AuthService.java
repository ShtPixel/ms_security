package com.uc.ms_security.service;

import com.uc.ms_security.dto.AuthResponseDTO;
import com.uc.ms_security.dto.LoginRequestDTO;
import com.uc.ms_security.dto.RegisterRequestDTO;
import com.uc.ms_security.dto.RegisterResponseDTO;
import com.uc.ms_security.dto.TwoFactorChallengeResponseDTO;
import com.uc.ms_security.dto.TwoFactorVerifyRequestDTO;
import com.uc.ms_security.dto.TwoFactorSettingsRequestDTO;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.entity.Session;
import com.uc.ms_security.entity.TwoFactorChallenge;
import com.uc.ms_security.mapper.UserMapper;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.repository.UserRepository;
import com.uc.ms_security.repository.SessionRepository;
import com.uc.ms_security.repository.TwoFactorChallengeRepository;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final UserMapper userMapper;
    private final SessionRepository sessionRepository;
    private final TwoFactorChallengeRepository challengeRepository;
    private final NotificationClient notificationClient;
    private final SecureRandom secureRandom = new SecureRandom();

    public Object login(LoginRequestDTO dto) {
        User user = userRepository.findByEmail(dto.getEmail()).orElseThrow(this::unauthorized);

        if (!user.isActive()) {
            throw unauthorized();
        }

        boolean validPassword = passwordEncoder.matches(dto.getPassword(),user.getPassword());

        if (!validPassword) {
            throw unauthorized();
        }

        if (!user.isTwoFactorEnabled()) {
            return completeLogin(user);
        }

        String code = "%06d".formatted(secureRandom.nextInt(1_000_000));
        TwoFactorChallenge challenge = new TwoFactorChallenge();
        challenge.setId(UUID.randomUUID().toString());
        challenge.setUser(user);
        challenge.setCodeHash(passwordEncoder.encode(code));
        challenge.setExpiresAt(Instant.now().plusSeconds(300));
        challenge.setAttempts(0);
        challenge.setConsumed(false);
        challengeRepository.save(challenge);
        try {
            notificationClient.sendTwoFactorCode(user.getEmail(), code);
        } catch (RuntimeException exception) {
            challengeRepository.delete(challenge);
            throw new ApplicationException(
                    ErrorCase.INVALID_OPERATION,
                    "No fue posible enviar el código de verificación"
            );
        }
        return new TwoFactorChallengeResponseDTO("verification_required", challenge.getId());
    }

    public AuthResponseDTO verifyTwoFactor(TwoFactorVerifyRequestDTO dto) {
        TwoFactorChallenge challenge = challengeRepository.findById(dto.challengeId())
                .orElseThrow(this::unauthorized);
        if (challenge.isConsumed() || challenge.getExpiresAt().isBefore(Instant.now())
                || challenge.getAttempts() >= 5) {
            throw unauthorized();
        }
        if (!passwordEncoder.matches(dto.code(), challenge.getCodeHash())) {
            challenge.setAttempts(challenge.getAttempts() + 1);
            challengeRepository.save(challenge);
            throw unauthorized();
        }
        challenge.setConsumed(true);
        challengeRepository.save(challenge);
        return completeLogin(challenge.getUser());
    }

    public void updateTwoFactor(Long userId, TwoFactorSettingsRequestDTO dto) {
        User user = userRepository.findById(userId).orElseThrow(this::unauthorized);
        if (!user.isActive() || !passwordEncoder.matches(dto.password(), user.getPassword())) {
            throw unauthorized();
        }
        user.setTwoFactorEnabled(dto.enabled());
        userRepository.save(user);
    }

    private AuthResponseDTO completeLogin(User user) {
        AuthResponseDTO response = jwtService.generateToken(user);
        Session session = new Session();
        session.setUser(user);
        session.setToken(response.accessToken());
        session.setExpiration(LocalDateTime.ofInstant(response.expiresAt(), ZoneOffset.UTC));
        sessionRepository.save(session);
        return response;
    }
    
    public RegisterResponseDTO register(RegisterRequestDTO dto) {
        if (userRepository.existsByEmail(dto.getEmail())) {
            throw new ApplicationException(
                    ErrorCase.ALREADY_EXISTS,
                    "El correo ya está registrado"
            );
        }

        String encodedPassword = passwordEncoder.encode(dto.getPassword());
        User user = userMapper.toEntity(dto, encodedPassword);
        User savedUser = userRepository.save(user);

        return new RegisterResponseDTO(
                savedUser.getId(),
                savedUser.getName(),
                savedUser.getEmail()
        );
    }

    private ApplicationException unauthorized() {
        return new ApplicationException(
                ErrorCase.UNAUTHORIZED,
                "Credenciales incorrectas"
        );
    }
}
