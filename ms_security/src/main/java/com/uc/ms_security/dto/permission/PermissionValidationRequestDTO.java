package com.uc.ms_security.dto.permission;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record PermissionValidationRequestDTO(
        @NotBlank
        @Size(max = 255)
        @Pattern(regexp = "^/(?!/)[^?#]*$")
        String url,

        @NotBlank
        @Pattern(regexp = "^(?i:GET|POST|PUT|PATCH|DELETE)$")
        String method
) {
}
