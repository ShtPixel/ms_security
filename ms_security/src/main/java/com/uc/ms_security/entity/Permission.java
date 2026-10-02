package com.uc.ms_security.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(
        name = "permissions",
        // no puede existir dos veces el mismo permiso (misma url + mismo método)
        uniqueConstraints = @UniqueConstraint(columnNames = {"url", "method"})
)
@Getter
@Setter
@NoArgsConstructor
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 255)
    private String url;     // ej: /api/users

    @Column(nullable = false, length = 10)
    private String method;  // ej: GET, POST, PUT, DELETE

    @Column(nullable = false, length = 100)
    private String model;   // ej: User, Role
}
