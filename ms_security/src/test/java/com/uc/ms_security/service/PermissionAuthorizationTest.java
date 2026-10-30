package com.uc.ms_security.service;

import com.uc.ms_security.entity.Permission;
import com.uc.ms_security.mapper.PermissionMapper;
import com.uc.ms_security.repository.PermissionRepository;
import com.uc.ms_security.repository.RolePermissionRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PermissionAuthorizationTest {

    @Mock
    private PermissionRepository permissionRepository;

    @Mock
    private RolePermissionRepository rolePermissionRepository;

    @Mock
    private PermissionMapper permissionMapper;

    @InjectMocks
    private PermissionService permissionService;

    @Test
    void normalizesNumericIdsAndHttpMethodBeforeCheckingPermission() {
        when(permissionRepository.findByUserIdAndMethodAndUrl(
                15L,
                "GET",
                "/api/users/{id}"
        )).thenReturn(List.of(new Permission()));

        assertTrue(permissionService.hasPermission(
                15L,
                "get",
                "/api/users/15"
        ));

        verify(permissionRepository).findByUserIdAndMethodAndUrl(
                15L,
                "GET",
                "/api/users/{id}"
        );
    }

    @Test
    void normalizesMongoObjectIdsAcrossUrlSegments() {
        when(permissionRepository.findByUserIdAndMethodAndUrl(
                15L,
                "DELETE",
                "/api/users/{id}/sessions/{id}"
        )).thenReturn(List.of(new Permission()));

        assertTrue(permissionService.hasPermission(
                15L,
                "DELETE",
                "/api/users/507F1F77BCF86CD799439011/sessions/507f1f77bcf86cd799439011"
        ));

        verify(permissionRepository).findByUserIdAndMethodAndUrl(
                15L,
                "DELETE",
                "/api/users/{id}/sessions/{id}"
        );
    }

    @Test
    void doesNotNormalizeUuids() {
        String url = "/api/users/550e8400-e29b-41d4-a716-446655440000";
        when(permissionRepository.findByUserIdAndMethodAndUrl(
                15L,
                "GET",
                url
        )).thenReturn(List.of(new Permission()));

        assertTrue(permissionService.hasPermission(15L, "GET", url));

        verify(permissionRepository).findByUserIdAndMethodAndUrl(
                15L,
                "GET",
                url
        );
    }
}
