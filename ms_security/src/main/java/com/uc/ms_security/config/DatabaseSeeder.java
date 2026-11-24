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

        // ==================== USERS ====================
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

        // ==================== PROFILES ====================
        new PermissionSeed("GET", "/api/users/{id}/profile", "Profile"),
        new PermissionSeed("POST", "/api/users/{id}/profile", "Profile"),
        new PermissionSeed("PUT", "/api/users/{id}/profile", "Profile"),
        new PermissionSeed("DELETE", "/api/users/{id}/profile", "Profile"),

        // ==================== SESSIONS ====================
        new PermissionSeed("GET", "/api/users/{id}/sessions", "Session"),
        new PermissionSeed("POST", "/api/users/{id}/sessions", "Session"),
        new PermissionSeed("GET", "/api/users/{id}/sessions/{id}", "Session"),
        new PermissionSeed("PUT", "/api/users/{id}/sessions/{id}", "Session"),
        new PermissionSeed("DELETE", "/api/users/{id}/sessions/{id}", "Session"),

        // ==================== ROLES ====================
        new PermissionSeed("GET", "/api/roles", "Role"),
        new PermissionSeed("POST", "/api/roles", "Role"),
        new PermissionSeed("GET", "/api/roles/{id}", "Role"),
        new PermissionSeed("GET", "/api/roles/{id}/detail-with-permissions", "Role"),
        new PermissionSeed("PUT", "/api/roles/{id}", "Role"),
        new PermissionSeed("DELETE", "/api/roles/{id}", "Role"),

        // ==================== PERMISSIONS ====================
        new PermissionSeed("GET", "/api/permissions", "Permission"),
        new PermissionSeed("POST", "/api/permissions", "Permission"),
        new PermissionSeed("GET", "/api/permissions/{id}", "Permission"),
        new PermissionSeed("PUT", "/api/permissions/{id}", "Permission"),
        new PermissionSeed("DELETE", "/api/permissions/{id}", "Permission"),

        // ==================== USER ROLES ====================
        new PermissionSeed("GET", "/api/user-roles", "UserRole"),
        new PermissionSeed("POST", "/api/user-roles", "UserRole"),
        new PermissionSeed("GET", "/api/user-roles/users/{id}", "UserRole"),
        new PermissionSeed("GET", "/api/user-roles/roles/{id}", "UserRole"),
        new PermissionSeed("DELETE", "/api/user-roles/{id}/{id}", "UserRole"),

        // ==================== ROLE PERMISSIONS ====================
        new PermissionSeed("GET", "/api/role-permissions", "RolePermission"),
        new PermissionSeed("POST", "/api/role-permissions", "RolePermission"),
        new PermissionSeed("GET", "/api/role-permissions/roles/{id}", "RolePermission"),
        new PermissionSeed("GET", "/api/role-permissions/permissions/{id}", "RolePermission"),
        new PermissionSeed("DELETE", "/api/role-permissions/{id}/{id}", "RolePermission"),

        // ==================== DEPORTES ====================
        new PermissionSeed("GET", "/api/deportes", "Deporte"),
        new PermissionSeed("POST", "/api/deportes", "Deporte"),
        new PermissionSeed("GET", "/api/deportes/{id}", "Deporte"),
        new PermissionSeed("PATCH", "/api/deportes/{id}", "Deporte"),
        new PermissionSeed("DELETE", "/api/deportes/{id}", "Deporte"),
        new PermissionSeed("GET", "/api/deportes/{id}/equipos", "Deporte"),
        new PermissionSeed("GET", "/api/deportes/{id}/subdeportes", "Deporte"),

        // ==================== EQUIPOS ====================
        new PermissionSeed("GET", "/api/equipos", "Equipo"),
        new PermissionSeed("POST", "/api/equipos", "Equipo"),
        new PermissionSeed("GET", "/api/equipos/{id}", "Equipo"),
        new PermissionSeed("PATCH", "/api/equipos/{id}", "Equipo"),
        new PermissionSeed("DELETE", "/api/equipos/{id}", "Equipo"),
        new PermissionSeed("GET", "/api/equipos/{id}/deportes", "Equipo"),
        new PermissionSeed("GET", "/api/equipos/{id}/jugadores", "Equipo"),

        // ==================== EQUIPOS - DEPORTES ====================
        new PermissionSeed("GET", "/api/equipos-deportes", "EquipoDeporte"),
        new PermissionSeed("POST", "/api/equipos-deportes", "EquipoDeporte"),
        new PermissionSeed("GET", "/api/equipos-deportes/{id}", "EquipoDeporte"),
        new PermissionSeed("PATCH", "/api/equipos-deportes/{id}", "EquipoDeporte"),
        new PermissionSeed("DELETE", "/api/equipos-deportes/{id}", "EquipoDeporte"),

        // ==================== JUGADORES ====================
        new PermissionSeed("GET", "/api/jugadores", "Jugador"),
        new PermissionSeed("POST", "/api/jugadores", "Jugador"),
        new PermissionSeed("GET", "/api/jugadores/{id}", "Jugador"),
        new PermissionSeed("PATCH", "/api/jugadores/{id}", "Jugador"),
        new PermissionSeed("DELETE", "/api/jugadores/{id}", "Jugador"),
        new PermissionSeed("GET", "/api/jugadores/{id}/perfil", "Jugador"),
        new PermissionSeed("GET", "/api/jugadores/{id}/equipos", "Jugador"),
        new PermissionSeed("GET", "/api/jugadores/{id}/habilidades", "Jugador"),

        // ==================== TORNEOS ====================
        new PermissionSeed("GET", "/api/torneos", "Torneo"),
        new PermissionSeed("POST", "/api/torneos", "Torneo"),
        new PermissionSeed("GET", "/api/torneos/{id}", "Torneo"),
        new PermissionSeed("PATCH", "/api/torneos/{id}", "Torneo"),
        new PermissionSeed("DELETE", "/api/torneos/{id}", "Torneo"),
        new PermissionSeed("GET", "/api/torneos/{id}/fases", "Torneo"),
        new PermissionSeed("GET", "/api/torneos/{id}/inscripciones", "Torneo"),
        new PermissionSeed("GET", "/api/torneos/{id}/escenarios", "Torneo"),

        // ==================== ESCENARIOS ====================
        new PermissionSeed("GET", "/api/escenarios", "Escenario"),
        new PermissionSeed("POST", "/api/escenarios", "Escenario"),
        new PermissionSeed("GET", "/api/escenarios/{id}", "Escenario"),
        new PermissionSeed("PATCH", "/api/escenarios/{id}", "Escenario"),
        new PermissionSeed("DELETE", "/api/escenarios/{id}", "Escenario"),
        new PermissionSeed("GET", "/api/escenarios/{id}/subescenarios", "Escenario"),
        new PermissionSeed("GET", "/api/escenarios/{id}/localidades", "Escenario"),
        new PermissionSeed("GET", "/api/escenarios/{id}/partidos", "Escenario"),

        // ==================== LOCALIDADES ====================
        new PermissionSeed("POST", "/api/localidades", "Localidad"),
        new PermissionSeed("GET", "/api/localidades", "Localidad"),
        new PermissionSeed("GET", "/api/localidades/{id}", "Localidad"),
        new PermissionSeed("PATCH", "/api/localidades/{id}", "Localidad"),
        new PermissionSeed("DELETE", "/api/localidades/{id}", "Localidad"),
        new PermissionSeed("GET", "/api/localidades/{id}/boletos", "Localidad"),

        // ==================== ESCENARIOS - TORNEOS ====================
        new PermissionSeed("POST", "/api/escenarios-torneos", "EscenarioTorneo"),
        new PermissionSeed("GET", "/api/escenarios-torneos", "EscenarioTorneo"),
        new PermissionSeed("GET", "/api/escenarios-torneos/{id}", "EscenarioTorneo"),
        new PermissionSeed("PATCH", "/api/escenarios-torneos/{id}", "EscenarioTorneo"),
        new PermissionSeed("DELETE", "/api/escenarios-torneos/{id}", "EscenarioTorneo"),

        // ==================== INSCRIPCIONES ====================
        new PermissionSeed("GET", "/api/inscripciones", "Inscripcion"),
        new PermissionSeed("POST", "/api/inscripciones", "Inscripcion"),
        new PermissionSeed("GET", "/api/inscripciones/{id}", "Inscripcion"),
        new PermissionSeed("PATCH", "/api/inscripciones/{id}", "Inscripcion"),
        new PermissionSeed("DELETE", "/api/inscripciones/{id}", "Inscripcion"),

        // ==================== FASES ====================
        new PermissionSeed("GET", "/api/fases", "Fase"),
        new PermissionSeed("POST", "/api/fases", "Fase"),
        new PermissionSeed("GET", "/api/fases/{id}", "Fase"),
        new PermissionSeed("PATCH", "/api/fases/{id}", "Fase"),
        new PermissionSeed("DELETE", "/api/fases/{id}", "Fase"),
        new PermissionSeed("GET", "/api/fases/{id}/partidos", "Fase"),
        new PermissionSeed("GET", "/api/fases/{id}/grupos", "Fase"),
        new PermissionSeed("GET", "/api/fases/{id}/final", "Fase"),

        // ==================== GRUPOS ====================
        new PermissionSeed("GET", "/api/grupos", "Grupo"),
        new PermissionSeed("POST", "/api/grupos", "Grupo"),
        new PermissionSeed("GET", "/api/grupos/{id}", "Grupo"),
        new PermissionSeed("PATCH", "/api/grupos/{id}", "Grupo"),
        new PermissionSeed("DELETE", "/api/grupos/{id}", "Grupo"),
        new PermissionSeed("GET", "/api/grupos/{id}/equipos", "Grupo"),

        // ==================== FINALES ====================
        new PermissionSeed("GET", "/api/finales", "Final"),
        new PermissionSeed("POST", "/api/finales", "Final"),
        new PermissionSeed("GET", "/api/finales/{id}", "Final"),
        new PermissionSeed("PATCH", "/api/finales/{id}", "Final"),
        new PermissionSeed("DELETE", "/api/finales/{id}", "Final"),

        // ==================== PARTIDOS ====================
        new PermissionSeed("GET", "/api/partidos", "Partido"),
        new PermissionSeed("POST", "/api/partidos", "Partido"),
        new PermissionSeed("GET", "/api/partidos/{id}", "Partido"),
        new PermissionSeed("PATCH", "/api/partidos/{id}", "Partido"),
        new PermissionSeed("DELETE", "/api/partidos/{id}", "Partido"),
        new PermissionSeed("GET", "/api/partidos/{id}/boletos", "Partido"),
        new PermissionSeed("GET", "/api/partidos/{id}/apuestas", "Partido"),

        // ==================== ANOTACIONES ====================
        new PermissionSeed("GET", "/api/anotaciones", "Anotacion"),
        new PermissionSeed("POST", "/api/anotaciones", "Anotacion"),
        new PermissionSeed("GET", "/api/anotaciones/{id}", "Anotacion"),
        new PermissionSeed("PATCH", "/api/anotaciones/{id}", "Anotacion"),
        new PermissionSeed("DELETE", "/api/anotaciones/{id}", "Anotacion"),

        // ==================== CONTRATOS ====================
        new PermissionSeed("POST", "/api/contratos", "Contrato"),
        new PermissionSeed("GET", "/api/contratos", "Contrato"),
        new PermissionSeed("GET", "/api/contratos/{id}", "Contrato"),
        new PermissionSeed("PATCH", "/api/contratos/{id}", "Contrato"),
        new PermissionSeed("PATCH", "/api/contratos/{id}/finalizar", "Contrato"),
        new PermissionSeed("DELETE", "/api/contratos/{id}", "Contrato"),

        // ==================== HABILIDADES ====================
        new PermissionSeed("POST", "/api/habilidades", "Habilidad"),
        new PermissionSeed("GET", "/api/habilidades", "Habilidad"),
        new PermissionSeed("GET", "/api/habilidades/{id}", "Habilidad"),
        new PermissionSeed("PATCH", "/api/habilidades/{id}", "Habilidad"),
        new PermissionSeed("DELETE", "/api/habilidades/{id}", "Habilidad"),
        new PermissionSeed("GET", "/api/habilidades/{id}/jugadores", "Habilidad"),

        // ==================== HABILIDADES - JUGADORES ====================
        new PermissionSeed("POST", "/api/habilidades-jugadores", "HabilidadJugador"),
        new PermissionSeed("GET", "/api/habilidades-jugadores", "HabilidadJugador"),
        new PermissionSeed("GET", "/api/habilidades-jugadores/{id}", "HabilidadJugador"),
        new PermissionSeed("PATCH", "/api/habilidades-jugadores/{id}", "HabilidadJugador"),
        new PermissionSeed("DELETE", "/api/habilidades-jugadores/{id}", "HabilidadJugador"),

        // ==================== AFICIONADOS ====================
        new PermissionSeed("POST", "/api/aficionados", "Aficionado"),
        new PermissionSeed("GET", "/api/aficionados", "Aficionado"),
        new PermissionSeed("GET", "/api/aficionados/{id}", "Aficionado"),
        new PermissionSeed("PATCH", "/api/aficionados/{id}", "Aficionado"),
        new PermissionSeed("DELETE", "/api/aficionados/{id}", "Aficionado"),
        new PermissionSeed("GET", "/api/aficionados/{id}/boletos", "Aficionado"),
        new PermissionSeed("GET", "/api/aficionados/{id}/metodos-pago", "Aficionado"),
        new PermissionSeed("GET", "/api/aficionados/{id}/apuestas", "Aficionado"),

        // ==================== METODOS DE PAGO ====================
        new PermissionSeed("POST", "/api/metodos-pago", "MetodoPago"),
        new PermissionSeed("GET", "/api/metodos-pago", "MetodoPago"),
        new PermissionSeed("GET", "/api/metodos-pago/{id}", "MetodoPago"),
        new PermissionSeed("PATCH", "/api/metodos-pago/{id}", "MetodoPago"),
        new PermissionSeed("DELETE", "/api/metodos-pago/{id}", "MetodoPago"),

        // ==================== METODOS DE PAGO - AFICIONADOS ====================
        new PermissionSeed("POST", "/api/metodos-pago-aficionados", "MetodoPagoAficionado"),
        new PermissionSeed("GET", "/api/metodos-pago-aficionados", "MetodoPagoAficionado"),
        new PermissionSeed("GET", "/api/metodos-pago-aficionados/{id}", "MetodoPagoAficionado"),
        new PermissionSeed("PATCH", "/api/metodos-pago-aficionados/{id}", "MetodoPagoAficionado"),
        new PermissionSeed("DELETE", "/api/metodos-pago-aficionados/{id}", "MetodoPagoAficionado"),

        // ==================== BOLETOS ====================
        new PermissionSeed("POST", "/api/boletos", "Boleto"),
        new PermissionSeed("GET", "/api/boletos", "Boleto"),
        new PermissionSeed("GET", "/api/boletos/{id}", "Boleto"),
        new PermissionSeed("PATCH", "/api/boletos/{id}", "Boleto"),
        new PermissionSeed("DELETE", "/api/boletos/{id}", "Boleto"),

        // ==================== APUESTAS ====================
        new PermissionSeed("POST", "/api/apuestas", "Apuesta"),
        new PermissionSeed("GET", "/api/apuestas", "Apuesta"),
        new PermissionSeed("GET", "/api/apuestas/{id}", "Apuesta"),
        new PermissionSeed("PATCH", "/api/apuestas/{id}", "Apuesta"),
        new PermissionSeed("DELETE", "/api/apuestas/{id}", "Apuesta"),

        // ==================== PELOTAS ====================
        new PermissionSeed("POST", "/api/pelotas", "Pelota"),
        new PermissionSeed("GET", "/api/pelotas", "Pelota"),
        new PermissionSeed("GET", "/api/pelotas/{id}", "Pelota"),
        new PermissionSeed("PATCH", "/api/pelotas/{id}", "Pelota"),
        new PermissionSeed("DELETE", "/api/pelotas/{id}", "Pelota"),

        // ==================== POSICIONES ESPACIALES ====================
        new PermissionSeed("POST", "/api/posiciones-espaciales", "PosicionEspacial"),
        new PermissionSeed("GET", "/api/posiciones-espaciales", "PosicionEspacial"),
        new PermissionSeed("GET", "/api/posiciones-espaciales/{id}", "PosicionEspacial"),
        new PermissionSeed("PATCH", "/api/posiciones-espaciales/{id}", "PosicionEspacial"),
        new PermissionSeed("DELETE", "/api/posiciones-espaciales/{id}", "PosicionEspacial"),

        // ==================== AFICIONADOS - EQUIPOS ====================
        new PermissionSeed("POST", "/api/aficionados-equipos", "AficionadoEquipo"),
        new PermissionSeed("GET", "/api/aficionados-equipos", "AficionadoEquipo"),
        new PermissionSeed("GET", "/api/aficionados-equipos/{id}", "AficionadoEquipo"),
        new PermissionSeed("PATCH", "/api/aficionados-equipos/{id}", "AficionadoEquipo"),
        new PermissionSeed("DELETE", "/api/aficionados-equipos/{id}", "AficionadoEquipo"),

        // ==================== UPLOADS ====================
        new PermissionSeed("GET", "/api/uploads/escudos/{archivo}", "Escudo")
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
