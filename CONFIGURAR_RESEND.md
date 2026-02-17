# 📧 Configuración de Resend para Emails

## ⚠️ ACCIÓN REQUERIDA

Para que funcione el envío de emails de recuperación de contraseña, necesitas configurar tu **API Key de Resend**.

## 📝 Pasos para configurar:

### 1. Obtener API Key de Resend

1. Ve a: **https://resend.com/api-keys**
2. Inicia sesión en tu cuenta de Resend
3. Crea una nueva API Key:
   - Nombre: `ForceGym Local Development`
   - Permisos: **Sending access**
4. **Copia la API Key** (comienza con `re_`)

### 2. Verificar dominio (IMPORTANTE)

Resend requiere que tu dominio de email esté verificado:

1. Ve a: **https://resend.com/domains**
2. Busca tu dominio: `forcegym.website`
3. Si no está verificado:
   - Agrega registros DNS según las instrucciones de Resend
   - Espera a que se verifique (puede tardar unos minutos)

### 3. Actualizar configuración local

Edita el archivo:
```
backend-ForceGym/src/main/resources/application-local.properties
```

Reemplaza esta línea:
```properties
RESEND_API_KEY=re_TU_API_KEY_REAL_AQUI
```

Por tu API Key real:
```properties
RESEND_API_KEY=re_tu_api_key_real_copiada_de_resend
```

### 4. Verificar configuración

Reinicia el backend y prueba enviando un email de recuperación de contraseña.

En la consola deberías ver:
```
📧 Enviando email via Resend API...
   Desde: no-reply@forcegym.website
   Para: usuario@ejemplo.com
   Asunto: Restablecimiento de contraseña
✅ Email enviado exitosamente via Resend
```

## 🚨 Errores comunes

### Error: "Domain not found"
- **Causa**: El dominio `forcegym.website` no está verificado en Resend
- **Solución**: Verifica el dominio en https://resend.com/domains

### Error: "Invalid API key"
- **Causa**: La API Key es incorrecta o ha sido revocada
- **Solución**: Genera una nueva API Key en https://resend.com/api-keys

### Error: "Rate limit exceeded"
- **Causa**: Has enviado demasiados emails en poco tiempo (límite gratuito)
- **Solución**: Espera unos minutos o actualiza tu plan de Resend

## 📊 Límites del plan gratuito de Resend

- **100 emails/día**
- **3,000 emails/mes**

Para producción, considera actualizar el plan si necesitas más volumen.

## 🔒 Seguridad

**NUNCA** subas tu API Key real al repositorio de GitHub. Las variables de entorno están en:
- **Local**: `application-local.properties` (ignorado por git)
- **Producción**: Variables de entorno en Railway

## ✅ Verificación

Una vez configurado, ejecuta:
```bash
curl -X POST http://localhost:8080/recoveryPassword \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=fromnowhereanyone@gmail.com"
```

Deberías recibir el email en la bandeja de entrada.
