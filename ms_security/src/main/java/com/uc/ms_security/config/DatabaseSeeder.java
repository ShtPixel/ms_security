package com.uc.ms_security.config;

import com.uc.ms_security.entity.Permission;
import com.uc.ms_security.entity.Role;
import com.uc.ms_security.entity.RolePermission;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.entity.UserRole;
import com.uc.ms_security.repository.PermissionRepository;
import com.uc.ms_security.repository.RolePermissionRepository;
import com.uc.ms_security.repository.RoleRepository;
import com.uc.ms_security.repository.UserRepository;
import com.uc.ms_security.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class DatabaseSeeder {

    private static final PermissionSeed[] ADMIN_PERMISSIONS = {
            new PermissionSeed("GET", "/api/users", "User"),
            new PermissionSeed("POST", "/api/users", "User"),
            new PermissionSeed("GET", "/api/users/{id}", "User"),
            new PermissionSeed("PUT", "/api/users/{id}", "User"),
            new PermissionSeed("DELETE", "/api/users/{id}", "User"),
            new PermissionSeed("GET", "/api/users/{id}/detail", "User"),
            new PermissionSeed("GET", "/api/users/{id}/detail-with-sessions", "User"),
            new PermissionSeed("GET", "/api/users/{id}/detail-with-roles", "User"),
            new PermissionSeed("GET", "/api/users/without-roles", "User"),
            new PermissionSeed("PATCH", "/api/users/{id}/deactivate", "User"),
            new PermissionSeed("PATCH", "/api/users/{id}/activate", "User"),
            new PermissionSeed("PATCH", "/api/users/{id}/2fa/activate", "User"),
            new PermissionSeed("PATCH", "/api/users/{id}/2fa/desactivate", "User"),
            new PermissionSeed("GET", "/api/users/{id}/profile", "Profile"),
            new PermissionSeed("POST", "/api/users/{id}/profile", "Profile"),
            new PermissionSeed("PUT", "/api/users/{id}/profile", "Profile"),
            new PermissionSeed("DELETE", "/api/users/{id}/profile", "Profile"),
            new PermissionSeed("GET", "/api/users/{id}/sessions", "Session"),
            new PermissionSeed("POST", "/api/users/{id}/sessions", "Session"),
            new PermissionSeed("GET", "/api/users/{id}/sessions/{id}", "Session"),
            new PermissionSeed("PUT", "/api/users/{id}/sessions/{id}", "Session"),
            new PermissionSeed("DELETE", "/api/users/{id}/sessions/{id}", "Session"),
            new PermissionSeed("GET", "/api/roles", "Role"),
            new PermissionSeed("POST", "/api/roles", "Role"),
            new PermissionSeed("GET", "/api/roles/{id}", "Role"),
            new PermissionSeed("GET", "/api/roles/{id}/detail-with-permissions", "Role"),
            new PermissionSeed("PUT", "/api/roles/{id}", "Role"),
            new PermissionSeed("DELETE", "/api/roles/{id}", "Role"),
            new PermissionSeed("GET", "/api/permissions", "Permission"),
            new PermissionSeed("POST", "/api/permissions", "Permission"),
            new PermissionSeed("GET", "/api/permissions/{id}", "Permission"),
            new PermissionSeed("PUT", "/api/permissions/{id}", "Permission"),
            new PermissionSeed("DELETE", "/api/permissions/{id}", "Permission"),
            new PermissionSeed("GET", "/api/user-roles", "UserRole"),
            new PermissionSeed("POST", "/api/user-roles", "UserRole"),
            new PermissionSeed("GET", "/api/user-roles/users/{id}", "UserRole"),
            new PermissionSeed("GET", "/api/user-roles/roles/{id}", "UserRole"),
            new PermissionSeed("DELETE", "/api/user-roles/{id}/{id}", "UserRole"),
            new PermissionSeed("GET", "/api/role-permissions", "RolePermission"),
            new PermissionSeed("POST", "/api/role-permissions", "RolePermission"),
            new PermissionSeed("GET", "/api/role-permissions/roles/{id}", "RolePermission"),
            new PermissionSeed("GET", "/api/role-permissions/permissions/{id}", "RolePermission"),
            new PermissionSeed("DELETE", "/api/role-permissions/{id}/{id}", "RolePermission"),
            
            new PermissionSeed("GET", "/api/deportes", "Deporte"),
            new PermissionSeed("POST", "/api/deportes", "Deporte"),
            new PermissionSeed("GET", "/api/deportes/{id}", "Deporte"),
            new PermissionSeed("PATCH", "/api/deportes/{id}", "Deporte"),
            new PermissionSeed("DELETE", "/api/deportes/{id}", "Deporte"),
            new PermissionSeed("GET", "/api/equipos", "Equipo"),
            new PermissionSeed("POST", "/api/equipos", "Equipo"),
            new PermissionSeed("GET", "/api/equipos/{id}", "Equipo"),
            new PermissionSeed("PATCH", "/api/equipos/{id}", "Equipo"),
            new PermissionSeed("DELETE", "/api/equipos/{id}", "Equipo"),
            new PermissionSeed("GET", "/api/jugadores", "Jugador"),
            new PermissionSeed("POST", "/api/jugadores", "Jugador"),
            new PermissionSeed("GET", "/api/jugadores/{id}", "Jugador"),
            new PermissionSeed("PATCH", "/api/jugadores/{id}", "Jugador"),
            new PermissionSeed("DELETE", "/api/jugadores/{id}", "Jugador"),
            new PermissionSeed("GET", "/api/torneos", "Torneo"),
            new PermissionSeed("POST", "/api/torneos", "Torneo"),
            new PermissionSeed("GET", "/api/torneos/{id}", "Torneo"),
            new PermissionSeed("PATCH", "/api/torneos/{id}", "Torneo"),
            new PermissionSeed("DELETE", "/api/torneos/{id}", "Torneo"),
            new PermissionSeed("GET", "/api/torneos/{id}/fases", "Torneo"),
            new PermissionSeed("GET", "/api/torneos/{id}/inscripciones", "Torneo"),
            new PermissionSeed("GET", "/api/torneos/{id}/escenarios", "Torneo"),
            new PermissionSeed("GET", "/api/inscripciones", "Inscripcion"),
            new PermissionSeed("POST", "/api/inscripciones", "Inscripcion"),
            new PermissionSeed("GET", "/api/inscripciones/{id}", "Inscripcion"),
            new PermissionSeed("PATCH", "/api/inscripciones/{id}", "Inscripcion"),
            new PermissionSeed("DELETE", "/api/inscripciones/{id}", "Inscripcion"),
            new PermissionSeed("GET", "/api/fases", "Fase"),
            new PermissionSeed("POST", "/api/fases", "Fase"),
            new PermissionSeed("GET", "/api/fases/{id}", "Fase"),
            new PermissionSeed("PATCH", "/api/fases/{id}", "Fase"),
            new PermissionSeed("DELETE", "/api/fases/{id}", "Fase"),
            new PermissionSeed("GET", "/api/fases/{id}/partidos", "Fase"),
            new PermissionSeed("GET", "/api/fases/{id}/grupos", "Fase"),
            new PermissionSeed("GET", "/api/fases/{id}/final", "Fase"),
            new PermissionSeed("GET", "/api/grupos", "Grupo"),
            new PermissionSeed("POST", "/api/grupos", "Grupo"),
            new PermissionSeed("GET", "/api/grupos/{id}", "Grupo"),
            new PermissionSeed("PATCH", "/api/grupos/{id}", "Grupo"),
            new PermissionSeed("DELETE", "/api/grupos/{id}", "Grupo"),
            new PermissionSeed("GET", "/api/grupos/{id}/equipos", "Grupo"),
            new PermissionSeed("GET", "/api/finales", "Final"),
            new PermissionSeed("POST", "/api/finales", "Final"),
            new PermissionSeed("GET", "/api/finales/{id}", "Final"),
            new PermissionSeed("PATCH", "/api/finales/{id}", "Final"),
            new PermissionSeed("DELETE", "/api/finales/{id}", "Final"),
            new PermissionSeed("GET", "/api/partidos", "Partido"),
            new PermissionSeed("POST", "/api/partidos", "Partido"),
            new PermissionSeed("GET", "/api/partidos/{id}", "Partido"),
            new PermissionSeed("PATCH", "/api/partidos/{id}", "Partido"),
            new PermissionSeed("DELETE", "/api/partidos/{id}", "Partido"),
            new PermissionSeed("GET", "/api/partidos/{id}/boletos", "Partido"),
            new PermissionSeed("GET", "/api/partidos/{id}/apuestas", "Partido"),
            new PermissionSeed("GET", "/api/anotaciones", "Anotacion"),
            new PermissionSeed("POST", "/api/anotaciones", "Anotacion"),
            new PermissionSeed("GET", "/api/anotaciones/{id}", "Anotacion"),
            new PermissionSeed("PATCH", "/api/anotaciones/{id}", "Anotacion"),
            new PermissionSeed("DELETE", "/api/anotaciones/{id}", "Anotacion"),
            new PermissionSeed("GET", "/api/escenarios", "Escenario"),
            new PermissionSeed("GET", "/api/escenarios/{id}", "Escenario")
    };

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRoleRepository userRoleRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${security.seed.admin-password:Admin123!}")
    private String adminPassword;

    @Bean
    CommandLineRunner seedDatabase() {
        return arguments -> {
            Role adminRole = findOrCreateRole("ADMIN", "Administrador");
            Role consultantRole = findOrCreateRole(
                    "CONSULTOR",
                    "Consulta de usuarios"
            );

            User adminUser = findOrCreateUser();
            assignRole(adminUser, adminRole);

            for (PermissionSeed seed : ADMIN_PERMISSIONS) {
                assignPermission(adminRole, findOrCreatePermission(seed));
            }

            revokePermission(consultantRole, "GET", "/api/users");
            assignPermission(
                    consultantRole,
                    findOrCreatePermission(
                            new PermissionSeed("GET", "/api/users/{id}", "User")
                    )
            );
        };
    }

    private Role findOrCreateRole(String name, String description) {
        return roleRepository.findByNameIgnoreCase(name)
                .orElseGet(() -> {
                    Role role = new Role();
                    role.setName(name);
                    role.setDescription(description);
                    return roleRepository.save(role);
                });
    }

    private User findOrCreateUser() {
        User adminUser = userRepository.findByEmail("admin@uc.edu.co")
                .orElseGet(() -> {
                    User user = new User();
                    user.setName("Administrador");
                    user.setEmail("admin@uc.edu.co");
                    user.setPassword(passwordEncoder.encode(adminPassword));
                    return user;
                });

        adminUser.setTwoFA(false);
        return userRepository.save(adminUser);
    }

    private Permission findOrCreatePermission(PermissionSeed seed) {
        return permissionRepository.findByUrlAndMethod(seed.url(), seed.method())
                .orElseGet(() -> {
                    Permission permission = new Permission();
                    permission.setUrl(seed.url());
                    permission.setMethod(seed.method());
                    permission.setModel(seed.model());
                    return permissionRepository.save(permission);
                });
    }

    private void assignRole(User user, Role role) {
        if (!userRoleRepository.existsByUserIdAndRoleId(
                user.getId(),
                role.getId()
        )) {
            UserRole userRole = new UserRole();
            userRole.setUser(user);
            userRole.setRole(role);
            userRoleRepository.save(userRole);
        }
    }

    private void assignPermission(Role role, Permission permission) {
        if (!rolePermissionRepository.existsByRoleIdAndPermissionId(
                role.getId(),
                permission.getId()
        )) {
            RolePermission rolePermission = new RolePermission();
            rolePermission.setRole(role);
            rolePermission.setPermission(permission);
            rolePermissionRepository.save(rolePermission);
        }
    }

    private void revokePermission(Role role, String method, String url) {
        permissionRepository.findByUrlAndMethod(url, method)
                .flatMap(permission -> rolePermissionRepository
                        .findByRoleIdAndPermissionId(role.getId(), permission.getId()))
                .ifPresent(rolePermissionRepository::delete);
    }

    private record PermissionSeed(String method, String url, String model) {
    }
}
