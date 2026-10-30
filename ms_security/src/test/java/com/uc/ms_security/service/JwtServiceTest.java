package com.uc.ms_security.service;

import com.uc.ms_security.config.JwtConfig;
import com.uc.ms_security.dto.AuthResponseDTO;
import com.uc.ms_security.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtException;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtServiceTest {

    private static final String SECRET = "clave-local-educativa-de-32-bytes";

    @Test
    void generatedTokenContainsExpectedClaimsAndCanBeDecoded() {
        JwtConfig config = new JwtConfig();
        SecretKey key = config.jwtSecretKey(SECRET);
        JwtEncoder encoder = config.jwtEncoder(key);
        JwtDecoder decoder = config.jwtDecoder(key);
        JwtService jwtService = new JwtService(encoder);

        User user = new User();
        user.setId(42L);
        user.setEmail("ana@mail.com");
        AuthResponseDTO response = jwtService.generateToken(user);

        Jwt decoded = decoder.decode(response.accessToken());

        assertEquals("Bearer", response.tokenType());
        assertEquals("ms-security", decoded.getClaimAsString("iss"));
        assertEquals("42", decoded.getSubject());
        assertEquals("ana@mail.com", decoded.getClaimAsString("email"));
        assertEquals(response.expiresAt(), decoded.getExpiresAt());
    }

    @Test
    void jwtSecretMustContainAtLeast32Bytes() {
        JwtConfig config = new JwtConfig();

        assertThrows(
                IllegalStateException.class,
                () -> config.jwtSecretKey("too-short")
        );
    }

    @Test
    void decoderRejectsTokenSignedWithDifferentSecret() {
        JwtConfig config = new JwtConfig();
        SecretKey signingKey = config.jwtSecretKey(SECRET);
        SecretKey otherKey = config.jwtSecretKey("another-local-secret-with-32-bytes");
        JwtService jwtService = new JwtService(config.jwtEncoder(signingKey));

        User user = new User();
        user.setId(42L);
        user.setEmail("ana@mail.com");
        String token = jwtService.generateToken(user).accessToken();

        assertThrows(
                JwtException.class,
                () -> config.jwtDecoder(otherKey).decode(token)
        );
    }
}
