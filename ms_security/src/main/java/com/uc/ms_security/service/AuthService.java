package com.uc.ms_security.service;

import com.uc.ms_security.dto.auth.AuthResponseDTO;
import com.uc.ms_security.dto.auth.LoginRequestDTO;
import com.uc.ms_security.dto.auth.LoginResultDTO;
import com.uc.ms_security.dto.auth.RegisterRequestDTO;
import com.uc.ms_security.dto.auth.RegisterResponseDTO;
import com.uc.ms_security.dto.auth.VerifyTwoFactorRequestDTO;
import com.uc.ms_security.entity.Session;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.mapper.UserMapper;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZoneOffset;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final UserMapper userMapper;
    private final TwoFactorAuthenticationService twoFactorAuthenticationService;

    public LoginResultDTO login(LoginRequestDTO dto) {
        User user = userRepository.findByEmail(dto.getEmail()).orElseThrow(this::unauthorized);

        boolean validPassword = passwordEncoder.matches(dto.getPassword(),user.getPassword());

        if (!validPassword) {
            throw unauthorized();
        }

        return startLogin(user);
    }

    @Transactional
    public AuthResponseDTO verifyTwoFactor(String challengeId, VerifyTwoFactorRequestDTO dto) {
        Session pendingSession = twoFactorAuthenticationService.verifyCode(
                challengeId,
                dto.getCode()
        );
        return jwtService.generateToken(pendingSession);
    }

    private LoginResultDTO startLogin(User user) {
        if (!user.isTwoFA()) {
            Session session = new Session();
            session.setUser(user);
            return new LoginResultDTO(jwtService.generateToken(session), null, null);
        }

        Session pendingSession = twoFactorAuthenticationService.sendCode(user);
        return new LoginResultDTO(
                new AuthResponseDTO(null, null, null),
                pendingSession.getToken(),
                pendingSession.getExpiration().toInstant(ZoneOffset.UTC)
        );
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
