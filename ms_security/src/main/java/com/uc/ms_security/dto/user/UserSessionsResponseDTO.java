package com.uc.ms_security.dto.user;

import com.uc.ms_security.dto.session.SessionResponseDTO;
import lombok.Value;

import java.util.List;

@Value
public class UserSessionsResponseDTO {
    Long id;
    String name;
    String email;
    boolean active;
    List<SessionResponseDTO> sessions;
}
