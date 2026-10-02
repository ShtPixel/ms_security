//Este DTO sirve para validar los datos cuando salen (informacion mostrada)

package com.uc.ms_security.dto.user;

import lombok.Value;

@Value
public class UserResponseDTO {
    Long id;
    String name;
    String email;
}