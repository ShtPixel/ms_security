package com.uc.ms_security.dto.session;

import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateSessionDTO extends BaseSessionDTO {

    // Si no se envía, se conserva el código actual (igual que la contraseña en User)
    @Pattern(regexp = "^[0-9]{6}$", message = "El código 2FA debe tener 6 dígitos")
    private String code2FA;
}
