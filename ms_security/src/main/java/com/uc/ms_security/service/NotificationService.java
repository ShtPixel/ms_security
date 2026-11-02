package com.uc.ms_security.service;

import com.uc.ms_security.dto.notification.NotificationRequestDTO;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class NotificationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationService.class);

    private final RestClient restClient;

    public NotificationService(
            RestClient.Builder restClientBuilder,
            @Value("${security.notification.base-url:http://localhost:5000}") String baseUrl) {
        this.restClient = restClientBuilder.baseUrl(baseUrl).build();
    }

    public void sendTwoFactorCode(String email, String code) {
        try {
            restClient.post()
                    .uri("/notifications/2fa")
                    .body(new NotificationRequestDTO(email, code))
                    .retrieve()
                    .toBodilessEntity();
        } catch (RestClientException exception) {
            LOGGER.error("Falló el envío del código 2FA al servicio de notificaciones", exception);
            throw new ApplicationException(
                    ErrorCase.SERVICE_UNAVAILABLE,
                    "No se pudo enviar el código de verificación",
                    exception
            );
        }
    }
}
