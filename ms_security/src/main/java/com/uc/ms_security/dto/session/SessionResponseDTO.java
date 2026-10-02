package com.uc.ms_security.dto.session;

import lombok.Value;

import java.time.LocalDateTime;

@Value
public class SessionResponseDTO { // no se devuelve el code2FA, por seguridad (como la contraseña)
    Long id;
    String token;
    LocalDateTime expiration;
}
