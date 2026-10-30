package com.uc.ms_security.dto.user;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserPasswordValidationTest {

    @Test
    void createRequiresStrongPassword() {
        CreateUserDTO dto = new CreateUserDTO();
        dto.setName("Ana Gómez");
        dto.setEmail("ana@mail.com");
        dto.setPassword("ClaveSegura123!");

        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            assertTrue(validator.validate(dto).isEmpty());

            dto.setPassword("clave123!");
            assertFalse(validator.validate(dto).isEmpty());
        }
    }

    @Test
    void updateAllowsOmittingPasswordButValidatesNewPassword() {
        UpdateUserDTO dto = new UpdateUserDTO();
        dto.setName("Ana Gómez");
        dto.setEmail("ana@mail.com");

        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            assertTrue(validator.validate(dto).isEmpty());

            dto.setPassword("Clave 123!");
            assertFalse(validator.validate(dto).isEmpty());
        }
    }
}
