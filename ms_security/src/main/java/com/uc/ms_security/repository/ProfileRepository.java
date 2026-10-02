package com.uc.ms_security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.uc.ms_security.entity.Profile;

public interface ProfileRepository extends JpaRepository<Profile, Long> {

    boolean existsByPhone(String phone);

    boolean existsByPhoneAndIdNot(String phone, Long id);

    Optional<Profile> findByUserId(Long userId);

    boolean existsByUserId(Long userId);
}
