package com.uc.ms_security.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class NotificationClient {

    private final ObjectMapper objectMapper;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    @Value("${notifications.base-url:http://127.0.0.1:5000}")
    private String baseUrl;

    @Value("${notifications.api-token:}")
    private String apiToken;

    public void sendTwoFactorCode(String email, String code) {
        if (apiToken.isBlank()) {
            throw new IllegalStateException("Falta configurar notifications.api-token");
        }
        try {
            String body = objectMapper.writeValueAsString(Map.of(
                    "to", email,
                    "subject", "Código de verificación",
                    "text", "Tu código de verificación es " + code + ". Vence en 5 minutos."
            ));
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl.replaceAll("/$", "") + "/send-email"))
                    .timeout(Duration.ofSeconds(10))
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .header("X-API-Key", apiToken)
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<Void> response = httpClient.send(
                    request, HttpResponse.BodyHandlers.discarding());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IllegalStateException("El servicio de notificaciones respondió " + response.statusCode());
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Se interrumpió el envío del código", exception);
        } catch (Exception exception) {
            throw new IllegalStateException("No se pudo enviar el código de verificación", exception);
        }
    }
}
