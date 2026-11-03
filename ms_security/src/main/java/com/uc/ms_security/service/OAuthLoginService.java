package com.uc.ms_security.service;

import com.uc.ms_security.dto.auth.AuthResponseDTO;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
public class OAuthLoginService {

    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();
    private static final long STATE_LIFETIME_SECONDS = 300;

    private final OAuthAccountService accountService;
    private final RestClient restClient;
    private final ConcurrentMap<String, PendingState> pendingStates = new ConcurrentHashMap<>();

    @Value("${security.oauth.google.client-id:}")
    private String googleClientId;
    @Value("${security.oauth.google.client-secret:}")
    private String googleClientSecret;
    @Value("${security.oauth.google.redirect-uri:http://localhost:3000/auth/callback/google}")
    private String googleRedirectUri;
    @Value("${security.oauth.github.client-id:}")
    private String githubClientId;
    @Value("${security.oauth.github.client-secret:}")
    private String githubClientSecret;
    @Value("${security.oauth.github.redirect-uri:http://localhost:3000/auth/callback/github}")
    private String githubRedirectUri;

    public OAuthLoginService(OAuthAccountService accountService, RestClient.Builder restClientBuilder) {
        this.accountService = accountService;
        this.restClient = restClientBuilder.build();
    }

    public String createState(String provider) {
        provider = normalizeProvider(provider);
        providerConfig(provider); // Fail clearly when provider credentials are not configured.
        pendingStates.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(Instant.now()));
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String state = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        pendingStates.put(state, new PendingState(provider, Instant.now().plusSeconds(STATE_LIFETIME_SECONDS)));
        return state;
    }

    public AuthResponseDTO exchange(String provider, String code, String redirectUri,
                                    String codeVerifier, String state, String stateCookie) {
        provider = normalizeProvider(provider);
        ProviderConfig config = providerConfig(provider);
        if (state == null || stateCookie == null || !constantTimeEquals(state, stateCookie)
                || codeVerifier == null || codeVerifier.length() < 43 || codeVerifier.length() > 128
                || !config.redirectUri().equals(redirectUri)) {
            throw invalidOAuthResponse();
        }

        PendingState pending = pendingStates.remove(state);
        if (pending == null || !pending.expiresAt().isAfter(Instant.now()) || !pending.provider().equals(provider)) {
            throw invalidOAuthResponse();
        }

        try {
            OAuthProfile profile = provider.equals("google")
                    ? fetchGoogleProfile(config, code, codeVerifier)
                    : fetchGitHubProfile(config, code, codeVerifier);
            return accountService.login(provider, profile.subject(), profile.email(), profile.name());
        } catch (RestClientException exception) {
            throw new ApplicationException(ErrorCase.UNAUTHORIZED,
                    "El proveedor rechazó la autenticación OAuth", exception);
        }
    }

    private OAuthProfile fetchGoogleProfile(ProviderConfig config, String code, String codeVerifier) {
        Map<?, ?> tokens = exchangeCode(
                "https://oauth2.googleapis.com/token", config, code, codeVerifier);
        if (tokens == null) throw invalidOAuthResponse();
        String accessToken = value(tokens, "access_token");
        if (accessToken == null) throw invalidOAuthResponse();
        Map<?, ?> userInfo = restClient.get()
                .uri("https://openidconnect.googleapis.com/v1/userinfo")
                .headers(headers -> headers.setBearerAuth(accessToken))
                .retrieve().body(Map.class);
        if (userInfo == null || !Boolean.TRUE.equals(userInfo.get("email_verified"))) {
            throw invalidOAuthResponse();
        }
        String subject = value(userInfo, "sub");
        String email = value(userInfo, "email");
        if (subject == null || email == null) throw invalidOAuthResponse();
        return new OAuthProfile(subject, email, value(userInfo, "name"));
    }

    private OAuthProfile fetchGitHubProfile(ProviderConfig config, String code, String codeVerifier) {
        Map<?, ?> tokens = exchangeCode(
                "https://github.com/login/oauth/access_token", config, code, codeVerifier);
        if (tokens == null) throw invalidOAuthResponse();
        String accessToken = value(tokens, "access_token");
        if (accessToken == null) throw invalidOAuthResponse();
        Map<?, ?> userInfo = restClient.get().uri("https://api.github.com/user")
                .headers(headers -> {
                    headers.setBearerAuth(accessToken);
                    headers.setAccept(List.of(MediaType.APPLICATION_JSON));
                    headers.set("X-GitHub-Api-Version", "2022-11-28");
                }).retrieve().body(Map.class);
        if (userInfo == null || userInfo.get("id") == null) throw invalidOAuthResponse();

        List<?> emails = restClient.get().uri("https://api.github.com/user/emails")
                .headers(headers -> {
                    headers.setBearerAuth(accessToken);
                    headers.setAccept(List.of(MediaType.APPLICATION_JSON));
                    headers.set("X-GitHub-Api-Version", "2022-11-28");
                }).retrieve().body(List.class);
        if (emails == null) throw invalidOAuthResponse();
        String email = emails.stream()
                .filter(item -> item instanceof Map<?, ?> emailItem
                        && Boolean.TRUE.equals(emailItem.get("primary"))
                        && Boolean.TRUE.equals(emailItem.get("verified")))
                .map(item -> value((Map<?, ?>) item, "email"))
                .filter(value -> value != null && !value.isBlank())
                .findFirst().orElseThrow(this::invalidOAuthResponse);
        String name = value(userInfo, "name");
        if (name == null || name.isBlank()) name = value(userInfo, "login");
        return new OAuthProfile(String.valueOf(userInfo.get("id")), email, name);
    }

    private Map<?, ?> exchangeCode(String tokenUri, ProviderConfig config,
                                   String code, String codeVerifier) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", config.clientId());
        form.add("client_secret", config.clientSecret());
        form.add("code", code);
        form.add("redirect_uri", config.redirectUri());
        form.add("code_verifier", codeVerifier);
        return restClient.post().uri(tokenUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .body(form).retrieve().body(Map.class);
    }

    private ProviderConfig providerConfig(String provider) {
        ProviderConfig config = provider.equals("google")
                ? new ProviderConfig(googleClientId, googleClientSecret, googleRedirectUri)
                : new ProviderConfig(githubClientId, githubClientSecret, githubRedirectUri);
        if (config.clientId() == null || config.clientId().isBlank()
                || config.clientSecret() == null || config.clientSecret().isBlank()
                || config.redirectUri() == null || config.redirectUri().isBlank()) {
            throw new ApplicationException(ErrorCase.SERVICE_UNAVAILABLE,
                    "El proveedor OAuth no está configurado en el servidor");
        }
        return config;
    }

    private String normalizeProvider(String provider) {
        if (provider == null) throw invalidOAuthResponse();
        String normalized = provider.toLowerCase(Locale.ROOT);
        if (!normalized.equals("google") && !normalized.equals("github")) throw invalidOAuthResponse();
        return normalized;
    }

    private String value(Map<?, ?> map, String key) {
        Object value = map.get(key);
        return value == null ? null : value.toString();
    }

    private boolean constantTimeEquals(String left, String right) {
        return java.security.MessageDigest.isEqual(left.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                right.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private ApplicationException invalidOAuthResponse() {
        return new ApplicationException(ErrorCase.UNAUTHORIZED, "La respuesta OAuth es inválida o expiró");
    }

    private record ProviderConfig(String clientId, String clientSecret, String redirectUri) { }
    private record PendingState(String provider, Instant expiresAt) { }
    private record OAuthProfile(String subject, String email, String name) { }
}
