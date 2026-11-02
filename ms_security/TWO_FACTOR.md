# Autenticación de dos factores por correo

`ms_security` solicita el código al microservicio Flask `ms_notifications`. El
JWT y la sesión interna solo se crean después de verificar el código cuando el
usuario tiene 2FA habilitado.

## Configuración local

Define el mismo secreto largo en las terminales de ambos servicios:

```powershell
$env:NOTIFICATION_API_TOKEN = "secreto-largo-compartido"
```

En la terminal de `ms_notifications`, inicia Flask como se indica en su README.
En la terminal de `ms_security`:

```powershell
$env:NOTIFICATIONS_BASE_URL = "http://127.0.0.1:5000"
.\gradlew.bat bootRun
```

## API de autenticación

Habilitar o deshabilitar requiere un JWT válido y confirmar la contraseña:

```http
PUT /api/auth/2fa
Authorization: Bearer <jwt>
Content-Type: application/json
```

```json
{"enabled": true, "password": "contraseña-actual"}
```

Con 2FA habilitado, `POST /api/auth/login` devuelve `202 Accepted` con un
`challengeId`. Verifica el código de seis dígitos recibido por correo:

```http
POST /api/auth/2fa/verify
Content-Type: application/json
```

```json
{"challengeId": "<challengeId>", "code": "123456"}
```

Los códigos vencen a los cinco minutos, permiten hasta cinco intentos y se
almacenan como hash. El reto se consume al verificarse correctamente. Si 2FA
está deshabilitado, el login conserva la respuesta con JWT. En ambos casos, la
sesión queda persistida al completar el login.
