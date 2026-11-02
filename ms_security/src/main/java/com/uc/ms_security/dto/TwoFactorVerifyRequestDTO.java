package com.uc.ms_security.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record TwoFactorVerifyRequestDTO(
        @NotBlank String challengeId,
        @NotBlank @Pattern(regexp = "\\d{6}") String code) {
}
