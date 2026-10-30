package com.uc.ms_security.dto.profile;

import java.time.LocalDate;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Size;
import com.fasterxml.jackson.annotation.JsonAlias;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ProfileRequestDTO {

    @NotBlank(
            message = "El teléfono es obligatorio"
    )
    private String phone;

    @NotNull(
            message = "La fecha de nacimiento es obligatoria"
    )
    @Past(
            message = "La fecha de nacimiento debe estar en el pasado"
    )
    private LocalDate birthDate;

    @Size(max = 500, message = "La fotografía no debe superar los 500 caracteres")
    @JsonAlias({"photoUrl", "photo_url", "fotografia"})
    private String photo;
}
