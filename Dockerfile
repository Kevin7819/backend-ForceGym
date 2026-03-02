# Etapa 1: Build con Maven
FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /app

# Copiar solo pom.xml primero para aprovechar el cache de Docker
COPY pom.xml .
# Descargar dependencias (se cachea si pom.xml no cambia)
RUN mvn dependency:go-offline -B

# Copiar el resto del código fuente
COPY src ./src

# Compilar la aplicación (solo se ejecuta si src/ cambió)
RUN mvn clean package -DskipTests -B

# Etapa 2: Runtime con imagen más ligera
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Crear usuario no-root para seguridad
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

# Copiar solo el JAR compilado desde la etapa de build
COPY --from=build /app/target/ForceGym-Backend.jar app.jar

# Exponer puerto
EXPOSE 8080

# Configurar JVM para contenedores con opciones optimizadas
ENTRYPOINT ["java", \
    "-XX:+UseContainerSupport", \
    "-XX:MaxRAMPercentage=75.0", \
    "-XX:+UseG1GC", \
    "-XX:+DisableExplicitGC", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-jar", \
    "app.jar"]
