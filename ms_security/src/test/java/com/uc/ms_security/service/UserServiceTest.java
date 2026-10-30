package com.uc.ms_security.service;

import com.uc.ms_security.dto.user.CreateUserDTO;
import com.uc.ms_security.dto.user.UpdateUserDTO;
import com.uc.ms_security.dto.user.UserResponseDTO;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.mapper.UserMapper;
import com.uc.ms_security.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    private static final Long USER_ID = 1L;
    private static final String CURRENT_HASH = "$2a$12$current-hash";
    private static final String NEW_HASH = "$2a$12$new-hash";

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserMapper userMapper;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;

    @Test
    void createStoresEncodedPasswordAndReturnsResponseDto() {
        CreateUserDTO dto = new CreateUserDTO();
        dto.setName("Ana Gómez");
        dto.setEmail("ana@mail.com");
        dto.setPassword("ClaveSegura123!");

        User user = new User();
        user.setPassword(NEW_HASH);
        UserResponseDTO response = new UserResponseDTO(USER_ID, "Ana Gómez", "ana@mail.com");

        when(userRepository.existsByEmail(dto.getEmail())).thenReturn(false);
        when(passwordEncoder.encode(dto.getPassword())).thenReturn(NEW_HASH);
        when(userMapper.toEntity(dto, NEW_HASH)).thenReturn(user);
        when(userRepository.save(user)).thenReturn(user);
        when(userMapper.toResponseDTO(user)).thenReturn(response);

        UserResponseDTO result = userService.create(dto);

        assertEquals(NEW_HASH, user.getPassword());
        assertSame(response, result);
        verify(userMapper).toEntity(dto, NEW_HASH);
    }

    @Test
    void updateWithoutPasswordPreservesExistingHash() {
        UpdateUserDTO dto = new UpdateUserDTO();
        dto.setName("Ana Gómez");
        dto.setEmail("ana@mail.com");

        User user = new User();
        user.setPassword(CURRENT_HASH);
        UserResponseDTO response = new UserResponseDTO(USER_ID, "Ana Gómez", "ana@mail.com");

        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user));
        when(userRepository.existsByEmailAndIdNot(dto.getEmail(), USER_ID)).thenReturn(false);
        when(userRepository.save(user)).thenReturn(user);
        when(userMapper.toResponseDTO(user)).thenReturn(response);

        userService.update(USER_ID, dto);

        assertEquals(CURRENT_HASH, user.getPassword());
        verify(passwordEncoder, never()).encode(dto.getPassword());
    }

    @Test
    void updateWithPasswordStoresNewEncodedPassword() {
        UpdateUserDTO dto = new UpdateUserDTO();
        dto.setName("Ana Gómez");
        dto.setEmail("ana@mail.com");
        dto.setPassword("NuevaClave123!");

        User user = new User();
        user.setPassword(CURRENT_HASH);
        UserResponseDTO response = new UserResponseDTO(USER_ID, "Ana Gómez", "ana@mail.com");

        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user));
        when(userRepository.existsByEmailAndIdNot(dto.getEmail(), USER_ID)).thenReturn(false);
        when(passwordEncoder.encode(dto.getPassword())).thenReturn(NEW_HASH);
        when(userRepository.save(user)).thenReturn(user);
        when(userMapper.toResponseDTO(user)).thenReturn(response);

        userService.update(USER_ID, dto);

        assertEquals(NEW_HASH, user.getPassword());
    }
}
