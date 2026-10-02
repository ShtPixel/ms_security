package com.uc.ms_security.dto.session;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public abstract class BaseSessionDTO {

    @NotBlank(message = "El token es obligatorio")
    @Size(max = 500, message = "El token no puede superar 500 caracteres")
    private String token;

    @NotNull(message = "La fecha de expiración es obligatoria")
    @Future(message = "La fecha de expiración debe ser futura")
    private LocalDateTime expiration;
}
