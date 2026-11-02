package com.uc.ms_security.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record TwoFactorSettingsRequestDTO(
        @NotNull Boolean enabled,
        @NotBlank String password) {
}
