package com.uc.ms_security.dto.auth;

import jakarta.validation.constraints.NotBlank;

public record OAuthExchangeRequestDTO(
        @NotBlank String code,
        @NotBlank String redirectUri,
        @NotBlank String codeVerifier,
        @NotBlank String state) {
}
