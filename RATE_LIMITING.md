# Rate Limiting - Portal de Clientes

## 📋 Resumen de Cambios

Se ha sustituido el reCAPTCHA por un sistema de **rate limiting basado en IP** para proteger el endpoint de login del portal de clientes contra ataques de fuerza bruta.

## 🔒 Configuración del Rate Limiting

### Parámetros de Seguridad

- **Intentos máximos**: 5 intentos por IP
- **Ventana de tiempo**: 1 minuto
- **Tiempo de bloqueo**: 5 minutos

### Funcionamiento

1. **Seguimiento de Intentos**: Cada intento de login fallido se registra por IP
2. **Límite de Intentos**: Después de 5 intentos fallidos en 1 minuto, la IP se bloquea
3. **Bloqueo Temporal**: La IP bloqueada no puede intentar login durante 5 minutos
4. **Limpieza Automática**: Los intentos exitosos limpian el contador de esa IP

## 🎯 Respuestas del Sistema

### Login Exitoso
```json
{
  "data": {
    "loggedClient": { ... },
    "message": "Login exitoso"
  },
  "message": "Login exitoso"
}
```

### Login Fallido (con intentos restantes)
```json
{
  "message": "Credenciales inválidas. Intentos restantes: 3"
}
```
**Status Code**: `401 UNAUTHORIZED`

### IP Bloqueada
```json
{
  "message": "Demasiados intentos fallidos. Por favor, intente nuevamente en 4 minutos."
}
```
**Status Code**: `429 TOO_MANY_REQUESTS`

### Bloqueo Completado
```json
{
  "message": "Demasiados intentos fallidos. Cuenta bloqueada temporalmente por 5 minutos."
}
```
**Status Code**: `401 UNAUTHORIZED`

## 🏗️ Arquitectura

### Backend

#### 1. LoginAttemptService
- **Ubicación**: `/backend-ForceGym/src/main/java/una/force_gym/service/LoginAttemptService.java`
- **Tecnología**: Caffeine Cache (almacenamiento en memoria)
- **Responsabilidades**:
  - Rastrear intentos de login por IP
  - Gestionar bloqueos temporales
  - Limpiar intentos exitosos

#### 2. IpUtils
- **Ubicación**: `/backend-ForceGym/src/main/java/una/force_gym/util/IpUtils.java`
- **Responsabilidad**: Obtener la IP real del cliente considerando proxies y load balancers
- **Headers considerados**:
  - X-Forwarded-For
  - Proxy-Client-IP
  - HTTP_X_FORWARDED_FOR
  - Y otros...

#### 3. ClientPortalController
- **Ubicación**: `/backend-ForceGym/src/main/java/una/force_gym/controller/ClientPortalController.java`
- **Modificaciones**:
  - Verifica bloqueos antes de procesar login
  - Registra intentos fallidos
  - Limpia intentos en logins exitosos
  - Proporciona feedback del estado de bloqueo

### Frontend

#### Cambios Realizados
1. **ClientLogin.tsx**: Removido componente ReCAPTCHA
2. **useClientLogin.ts**: Removida lógica de validación de reCAPTCHA
3. **types/index.ts**: Removido campo `recaptchaToken` de `ClientCredentials`
4. **clientPortalService.ts**: Actualizado para no enviar token de reCAPTCHA

## 📦 Dependencias Añadidas

### pom.xml
```xml
<dependency>
    <groupId>com.github.ben-manes.caffeine</groupId>
    <artifactId>caffeine</artifactId>
</dependency>
```

## 🧪 Casos de Prueba Sugeridos

### Caso 1: Login Exitoso
1. Ingresar credenciales válidas
2. Verificar que el login es exitoso
3. Verificar que los intentos se limpian

### Caso 2: Intentos Fallidos
1. Ingresar credenciales inválidas 3 veces
2. Verificar mensaje con intentos restantes
3. Verificar que muestra "Intentos restantes: 2", luego "1", etc.

### Caso 3: Bloqueo por Intentos
1. Ingresar credenciales inválidas 5 veces
2. Verificar que la IP se bloquea
3. Verificar mensaje de bloqueo temporal
4. Intentar nuevamente y verificar mensaje de tiempo restante

### Caso 4: Desbloqueo Automático
1. Bloquear una IP
2. Esperar 5 minutos
3. Verificar que se puede intentar login nuevamente

### Caso 5: Login Exitoso Limpia Bloqueo
1. Tener 3 intentos fallidos
2. Ingresar credenciales válidas
3. Verificar que los intentos se resetean a 0

## 🔧 Configuración Personalizada

Si se desea modificar los parámetros del rate limiting, editar las constantes en `LoginAttemptService.java`:

```java
private static final int MAX_ATTEMPTS = 5;              // Intentos máximos
private static final int ATTEMPT_WINDOW_MINUTES = 1;    // Ventana de tiempo
private static final int BLOCK_DURATION_MINUTES = 5;    // Duración del bloqueo
```

## 🚀 Ventajas sobre reCAPTCHA

1. **Mejor UX**: No molesta al usuario legítimo
2. **Sin dependencias externas**: No requiere servicios de Google
3. **Sin latencia adicional**: No hay llamadas a APIs externas
4. **Privacidad**: No se comparten datos con terceros
5. **Efectividad**: Detiene ataques de fuerza bruta
6. **Configuración flexible**: Fácil ajuste de parámetros

## 📝 Logs del Sistema

El sistema genera logs informativos:

```
✅ Login exitoso - IP: 192.168.1.100
❌ Login fallido - IP: 192.168.1.100 - Intentos restantes: 4
🚫 IP bloqueada por exceder intentos: 192.168.1.100
🚫 Intento de login bloqueado - IP: 192.168.1.100
```

## 🔐 Seguridad Adicional Recomendada

Para mejorar aún más la seguridad, considerar implementar:

1. **Rate limiting por usuario**: Además de por IP
2. **Lista de IPs bloqueadas persistente**: En caso de ataques repetidos
3. **Notificaciones**: Alertas cuando se detectan múltiples intentos fallidos
4. **Captcha progresivo**: Mostrar CAPTCHA solo después de 2-3 intentos fallidos
5. **Autenticación de dos factores (2FA)**: Para cuentas sensibles

## 🐛 Solución de Problemas

### Problema: "Bloqueado permanentemente"
- **Causa**: Cache de Caffeine no está expirando correctamente
- **Solución**: Verificar que el servicio LoginAttemptService esté correctamente inyectado

### Problema: "Bloqueos no funcionan"
- **Causa**: IP no se detecta correctamente
- **Solución**: Verificar logs para ver la IP detectada. Ajustar IpUtils si es necesario.

### Problema: "Múltiples IPs por cliente"
- **Causa**: Proxies, VPNs o NAT
- **Solución**: Considerar implementar rate limiting adicional por usuario

## 📊 Monitoreo

Para producción, se recomienda:

1. Agregar métricas de Caffeine
2. Monitorear número de IPs bloqueadas
3. Alertas de seguridad cuando hay picos de intentos fallidos
4. Dashboard de intentos de login por IP/región
