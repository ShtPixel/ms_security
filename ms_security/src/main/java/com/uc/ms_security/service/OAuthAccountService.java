package com.uc.ms_security.service;

import com.uc.ms_security.dto.auth.AuthResponseDTO;
import com.uc.ms_security.entity.OAuthIdentity;
import com.uc.ms_security.entity.Role;
import com.uc.ms_security.entity.Session;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.entity.UserRole;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.repository.OAuthIdentityRepository;
import com.uc.ms_security.repository.RoleRepository;
import com.uc.ms_security.repository.UserRepository;
import com.uc.ms_security.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Locale;

@Service
@RequiredArgsConstructor
public class OAuthAccountService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private final UserRepository userRepository;
    private final OAuthIdentityRepository identityRepository;
    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Transactional
    public AuthResponseDTO login(String provider, String subject, String email, String name) {
        OAuthIdentity identity = identityRepository.findByProviderAndProviderUserId(provider, subject)
                .orElse(null);
        User user;
        if (identity != null) {
            user = identity.getUser();
        } else {
            String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
            if (userRepository.existsByEmail(normalizedEmail)) {
                throw new ApplicationException(ErrorCase.ALREADY_EXISTS,
                        "Ya existe una cuenta con este correo; inicia sesión y vincula el proveedor desde tu cuenta");
            }
            user = new User();
            user.setEmail(normalizedEmail);
            user.setName(truncateName(name, normalizedEmail));
            user.setPassword(passwordEncoder.encode(randomPassword()));
            user = userRepository.save(user);

            Role consultantRole = roleRepository.findByNameIgnoreCase("CONSULTOR")
                    .orElseThrow(() -> new ApplicationException(ErrorCase.SERVICE_UNAVAILABLE,
                            "No está configurado el rol inicial para cuentas OAuth"));
            UserRole assignment = new UserRole();
            assignment.setUser(user);
            assignment.setRole(consultantRole);
            userRoleRepository.save(assignment);

            OAuthIdentity newIdentity = new OAuthIdentity();
            newIdentity.setProvider(provider);
            newIdentity.setProviderUserId(subject);
            newIdentity.setUser(user);
            identityRepository.save(newIdentity);
        }

        if (!user.isActive()) {
            throw new ApplicationException(ErrorCase.UNAUTHORIZED, "La cuenta está desactivada");
        }
        Session session = new Session();
        session.setUser(user);
        return jwtService.generateToken(session);
    }

    private String randomPassword() {
        byte[] bytes = new byte[48];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String truncateName(String name, String email) {
        String result = name == null || name.isBlank() ? email.substring(0, email.indexOf('@')) : name.trim();
        return result.length() > 100 ? result.substring(0, 100) : result;
    }
}
