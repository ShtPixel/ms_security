package com.uc.ms_security.controller;

import com.uc.ms_security.dto.session.CreateSessionDTO;
import com.uc.ms_security.dto.session.UpdateSessionDTO;
import com.uc.ms_security.dto.session.SessionResponseDTO;
import com.uc.ms_security.service.SessionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/sessions")
@RequiredArgsConstructor
public class SessionController {

    private final SessionService sessionService;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public SessionResponseDTO create(@Valid @RequestBody CreateSessionDTO dto) {
        return sessionService.create(dto);
    }

    @GetMapping
    public List<SessionResponseDTO> findAll() {
        return sessionService.findAll();
    }

    @GetMapping("/{id}")
    public SessionResponseDTO findById(@PathVariable Long id) {
        return sessionService.findById(id);
    }

    @PutMapping("/{id}")
    public SessionResponseDTO update(
            @PathVariable Long id,
            @Valid @RequestBody UpdateSessionDTO dto) {
        return sessionService.update(id, dto);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable Long id) {
        sessionService.delete(id);
    }
}
