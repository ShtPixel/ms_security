package com.uc.ms_security.controller;

import com.uc.ms_security.dto.permission.PermissionValidationRequestDTO;
import com.uc.ms_security.dto.permission.PermissionValidationResponseDTO;
import com.uc.ms_security.service.PermissionService;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/internal/security")
public class InternalSecurityController {

    private final PermissionService permissionService;

    public InternalSecurityController(PermissionService permissionService) {
        this.permissionService = permissionService;
    }

    @PostMapping("/permissions-validation")
    public PermissionValidationResponseDTO validatePermission(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody PermissionValidationRequestDTO request
    ) {
        String subject = jwt.getSubject();
        if (subject == null) {
            return new PermissionValidationResponseDTO(false);
        }

        Long userId;
        try {
            userId = Long.valueOf(subject);
        } catch (NumberFormatException exception) {
            return new PermissionValidationResponseDTO(false);
        }

        boolean allowed = permissionService.hasPermission(
                userId,
                request.method(),
                request.url()
        );
        return new PermissionValidationResponseDTO(allowed);
    }
}
