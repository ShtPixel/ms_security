package com.uc.ms_security.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.uc.ms_security.dto.session.CreateSessionDTO;
import com.uc.ms_security.dto.session.SessionResponseDTO;
import com.uc.ms_security.dto.session.UpdateSessionDTO;
import com.uc.ms_security.entity.Session;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.mapper.SessionMapper;
import com.uc.ms_security.repository.SessionRepository;
import com.uc.ms_security.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class SessionService {

    private final SessionRepository sessionRepository;

    private final UserRepository userRepository;

    private final SessionMapper sessionMapper;

    public SessionResponseDTO create(Long userId, CreateSessionDTO dto) {
        User user = findUser(userId);

        if (sessionRepository.existsByToken(dto.getToken())) {
            throw new ApplicationException(
                    ErrorCase.ALREADY_EXISTS,
                    "Ya existe una sesión con este token"
            );
        }
        Session session = sessionMapper.toEntity(dto);
        session.setUser(user);
        Session savedSession = sessionRepository.save(session);
        return sessionMapper.toResponseDTO(savedSession);
    }

    public List<SessionResponseDTO> findAllByUserId(Long userId) {
        findUser(userId);
        List<Session> sessions = sessionRepository.findAllByUserId(userId);
        return sessionMapper.toResponseDTOList(sessions);
    }

    private User findUser(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new ApplicationException(
                        ErrorCase.NOT_FOUND,
                        "Usuario no encontrado con id: " + userId
                ));
    }

    private Session findSession(Long userId, Long sessionId) {
        return sessionRepository.findByIdAndUserId(sessionId, userId)
                .orElseThrow(() -> new ApplicationException(
                        ErrorCase.NOT_FOUND,
                        "Sesión no encontrada para este usuario"
                ));
    }

    public SessionResponseDTO findById(Long userId, Long sessionId) {
        Session session = findSession(userId, sessionId);
        return sessionMapper.toResponseDTO(session);
    }

    public SessionResponseDTO update(Long userId, Long sessionId, UpdateSessionDTO dto) {
        Session session = findSession(userId, sessionId);
        if (sessionRepository.existsByTokenAndIdNot(dto.getToken(), sessionId)) {
            throw new ApplicationException(
                    ErrorCase.ALREADY_EXISTS,
                    "El token pertenece a otra sesión"
            );
        }
        sessionMapper.updateEntity(dto, session);
        Session updatedSession = sessionRepository.save(session);
        return sessionMapper.toResponseDTO(updatedSession);
    }

    public void delete(Long userId, Long sessionId) {
        Session session = findSession(userId, sessionId);
        sessionRepository.delete(session);
    }
}
