package com.uc.ms_security.service;

import org.springframework.stereotype.Service;

import com.uc.ms_security.dto.profile.CreateProfileDTO;
import com.uc.ms_security.dto.profile.ProfileResponseDTO;
import com.uc.ms_security.dto.profile.UpdateProfileDTO;
import com.uc.ms_security.entity.Profile;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.mapper.ProfileMapper;
import com.uc.ms_security.repository.ProfileRepository;
import com.uc.ms_security.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class ProfileService {

    private final ProfileRepository profileRepository;

    private final ProfileMapper profileMapper;

    private final UserRepository userRepository;

    public ProfileResponseDTO create(Long userId, CreateProfileDTO dto) {
        User user = findUser(userId);
        if (profileRepository.existsByUserId(userId)) {
            throw new ApplicationException(
                    ErrorCase.ALREADY_EXISTS,
                    "El usuario ya tiene un perfil"
            );
        }

        if (profileRepository.existsByPhone(dto.getPhone())) {
            throw new ApplicationException(
                    ErrorCase.ALREADY_EXISTS,
                    "Ya existe un perfil con este teléfono"
            );
        }

        Profile profile = profileMapper.toEntity(dto);
        profile.setUser(user);
        Profile savedProfile = profileRepository.save(profile);
        return profileMapper.toResponseDTO(savedProfile);
    }

    public ProfileResponseDTO updateByUserId(Long userId, UpdateProfileDTO dto) {
        Profile profile = findProfileByUserId(userId);
        if (profileRepository.existsByPhoneAndIdNot(dto.getPhone(), profile.getId())) {
            throw new ApplicationException(
                    ErrorCase.ALREADY_EXISTS,
                    "El teléfono pertenece a otro perfil"
            );
        }
        profileMapper.updateEntity(dto, profile);
        Profile updatedProfile = profileRepository.save(profile);
        return profileMapper.toResponseDTO(updatedProfile);
    }

    /** Creates or updates only the profile belonging to the authenticated user's ID. */
    public ProfileResponseDTO saveOwnProfile(Long userId, UpdateProfileDTO dto) {
        return profileRepository.findByUserId(userId)
                .map(profile -> {
                    if (profileRepository.existsByPhoneAndIdNot(dto.getPhone(), profile.getId())) {
                        throw new ApplicationException(
                                ErrorCase.ALREADY_EXISTS,
                                "El teléfono pertenece a otro perfil"
                        );
                    }
                    profileMapper.updateEntity(dto, profile);
                    return profileMapper.toResponseDTO(profileRepository.save(profile));
                })
                .orElseGet(() -> {
                    if (profileRepository.existsByPhone(dto.getPhone())) {
                        throw new ApplicationException(
                                ErrorCase.ALREADY_EXISTS,
                                "Ya existe un perfil con este teléfono"
                        );
                    }
                    User user = findUser(userId);
                    Profile profile = profileMapper.toEntity(dto);
                    profile.setUser(user);
                    return profileMapper.toResponseDTO(profileRepository.save(profile));
                });
    }

    public ProfileResponseDTO findByUserId(Long userId) {
        return profileMapper.toResponseDTO(findProfileByUserId(userId));
    }

    public void deleteByUserId(Long userId) {
        profileRepository.delete(findProfileByUserId(userId));
    }

    private User findUser(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new ApplicationException(
                        ErrorCase.NOT_FOUND,
                        "Usuario no encontrado con id: " + userId
                ));
    }

    private Profile findProfileByUserId(Long userId) {
        return profileRepository.findByUserId(userId)
                .orElseThrow(() -> new ApplicationException(
                        ErrorCase.NOT_FOUND,
                        "Perfil no encontrado para el usuario con id: " + userId
                ));
    }
}
