package com.uc.ms_security.dto.session;

import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateSessionDTO extends BaseSessionDTO {

    // Opcional: @Pattern acepta null, solo valida si viene un valor
    @Pattern(regexp = "^[0-9]{6}$", message = "El código 2FA debe tener 6 dígitos")
    private String code2FA;
}
