package com.uc.ms_security.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Entity //crea una tabla en la base de datos
@Table(name = "users") //nombre de la tabla
@Getter //pueden generar los getters y setters de forma automática
@Setter
@NoArgsConstructor // no se define la clase sino que lombook se encarga de crearlo
public class User {

    @Id  //traduce el codigo a la base de datos
    @GeneratedValue(
            strategy = GenerationType.IDENTITY
    )
    private Long id;  //atributo de la clase equivalente a la columna de la tabla

    @Column(
            nullable = false,
            length = 100
    )
    private String name; // atributo de la clase equivalente a la columna de la tabla

    @Column(  //atributo de la clase equivalente a la columna de la tabla
            nullable = false,
            unique = true,
            length = 150
    )
    private String email;

    @Column(
            nullable = false
    )
    private String password;

    @OneToOne(
            mappedBy = "user",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.LAZY
    )
    private Profile profile;

    @OneToMany(
            mappedBy = "user",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.LAZY
    )
    private List<Session> sessions = new ArrayList<>();
}

