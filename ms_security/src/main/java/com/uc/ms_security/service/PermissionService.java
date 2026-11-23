package com.uc.ms_security.service;

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;

import com.uc.ms_security.dto.permission.CreatePermissionDTO;
import com.uc.ms_security.dto.permission.PermissionResponseDTO;
import com.uc.ms_security.dto.permission.UpdatePermissionDTO;
import com.uc.ms_security.entity.Permission;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.mapper.PermissionMapper;
import com.uc.ms_security.repository.PermissionRepository;
import com.uc.ms_security.repository.RolePermissionRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class PermissionService {

    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();
    private static final Pattern RESOURCE_ID =
            Pattern.compile(
                    "^(?:\\d+|[a-fA-F0-9]{24}|"
                            + "[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12})$"
            );

    private final PermissionRepository permissionRepository;

    private final RolePermissionRepository rolePermissionRepository;

    private final PermissionMapper permissionMapper;

    public PermissionResponseDTO create(CreatePermissionDTO dto) {
        String method = normalizeMethod(dto.getMethod());
        if (permissionRepository.existsByUrlAndMethod(dto.getUrl(), method)) {
            throw new ApplicationException(
                    ErrorCase.ALREADY_EXISTS,
                    "Ya existe un permiso para " + method + " " + dto.getUrl()
            );
        }
        dto.setMethod(method);
        Permission permission = permissionMapper.toEntity(dto);
        Permission savedPermission = permissionRepository.save(permission);
        return permissionMapper.toResponseDTO(savedPermission);
    }

    public List<PermissionResponseDTO> findAll() {
        List<Permission> permissions = permissionRepository.findAll();
        return permissionMapper.toResponseDTOList(permissions);
    }

    private Permission findPermission(Long id) {
        return permissionRepository.findById(id)
                .orElseThrow(() -> new ApplicationException(
                ErrorCase.NOT_FOUND,
                "Permiso no encontrado con id: " + id
        ));
    }

    public PermissionResponseDTO findById(Long id) {
        Permission permission = findPermission(id);
        return permissionMapper.toResponseDTO(permission);
    }

    public PermissionResponseDTO update(Long id, UpdatePermissionDTO dto) {
        Permission permission = findPermission(id);
        String method = normalizeMethod(dto.getMethod());
        if (permissionRepository.existsByUrlAndMethodAndIdNot(dto.getUrl(), method, id)) {
            throw new ApplicationException(
                    ErrorCase.ALREADY_EXISTS,
                    "Ya existe otro permiso para " + method + " " + dto.getUrl()
            );
        }
        dto.setMethod(method);
        permissionMapper.updateEntity(dto, permission);
        Permission updatedPermission = permissionRepository.save(permission);
        return permissionMapper.toResponseDTO(updatedPermission);
    }

    public void delete(Long id) {
        Permission permission = findPermission(id);
        if (rolePermissionRepository.existsByPermissionId(id)) {
            throw new ApplicationException(
                    ErrorCase.INVALID_OPERATION,
                    "No se puede eliminar un permiso que está asignado"
            );
        }
        permissionRepository.delete(permission);
    }

    public boolean hasPermission(
            Long userId,
            String httpMethod,
            String requestUrl
    ) {
        return permissionRepository.findByUserIdAndMethod(
                userId,
                normalizeMethod(httpMethod)
        ).stream().anyMatch(permission ->
                matchesParameterizedUrl(permission.getUrl(), requestUrl)
        );
    }

    private boolean matchesParameterizedUrl(
            String permissionUrl,
            String requestUrl
    ) {
        if (!PATH_MATCHER.match(permissionUrl, requestUrl)) {
            return false;
        }

        String[] permissionSegments = permissionUrl.split("/", -1);
        String[] requestSegments = requestUrl.split("/", -1);
        if (permissionSegments.length != requestSegments.length) {
            return false;
        }

        for (int index = 0; index < permissionSegments.length; index++) {
            String segment = permissionSegments[index];
            if (segment.startsWith("{")
                    && segment.endsWith("}")
                    && !RESOURCE_ID.matcher(requestSegments[index]).matches()) {
                return false;
            }
        }
        return true;
    }

    private String normalizeMethod(String method) {
        return method.toUpperCase(Locale.ROOT);
    }
}
