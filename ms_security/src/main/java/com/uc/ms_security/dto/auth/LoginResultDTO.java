package com.uc.ms_security.dto.auth;

import java.time.Instant;

public record LoginResultDTO(
        AuthResponseDTO response,
        String challengeId,
        Instant challengeExpiresAt) {
}
