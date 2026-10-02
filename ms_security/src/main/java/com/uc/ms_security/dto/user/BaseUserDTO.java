package com.uc.ms_security.dto.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public abstract class BaseUserDTO {

    @NotBlank( //El nombre no debe quedar en blanco
            message = "El nombre es obligatorio"
    )
    @Size(
            min = 2, //Rango minimo del nombre
            max = 100, //Rango maximo del nombre
            message = "El nombre debe tener entre 2 y 100 caracteres"
    )
    private String name;

    @NotBlank( //El correo no debe estar en blanco
            message = "El email es obligatorio"
    )
    @Email( //El campo de email debe tener un formato valido
            message = "El email no tiene un formato válido"
    )
    private String email;
}
