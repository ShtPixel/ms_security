package com.uc.ms_security.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "sessions")
@Getter
@Setter
@NoArgsConstructor
public class Session {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 500) // largo para soportar tokens tipo JWT
    private String token;

    @Column(nullable = false)
    private LocalDateTime expiration; // fecha y hora exacta en que vence la sesión

    @Column(name = "code_2fa", length = 60)
    private String code2FA;

    @Column(nullable = false, columnDefinition = "boolean not null default true")
    private boolean authenticated = true;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
}
