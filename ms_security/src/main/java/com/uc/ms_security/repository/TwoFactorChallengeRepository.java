package com.uc.ms_security.repository;

import com.uc.ms_security.entity.TwoFactorChallenge;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TwoFactorChallengeRepository extends JpaRepository<TwoFactorChallenge, String> {
}
