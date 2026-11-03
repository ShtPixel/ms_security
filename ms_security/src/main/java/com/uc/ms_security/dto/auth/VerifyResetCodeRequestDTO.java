package com.uc.ms_security.dto.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record VerifyResetCodeRequestDTO(
        @NotBlank(message = "El correo es obligatorio")
        @Email(message = "El correo no tiene un formato válido")
        String email,

        @NotBlank(message = "El código es obligatorio")
        @Size(min = 6, max = 6, message = "El código debe tener 6 dígitos")
        String code
) {}

