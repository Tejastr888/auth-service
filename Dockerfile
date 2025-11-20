# Build stage
#FROM maven:3.9-eclipse-temurin-17-alpine AS build
FROM maven:3.9-eclipse-temurin-21-alpine AS build

WORKDIR /app

# Copy pom.xml and download dependencies (cached layer)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code
COPY src ./src

# Build the application
RUN mvn clean package -DskipTests -B

# Runtime stage
#FROM eclipse-temurin:17-jre-alpine
FROM eclipse-temurin:21-jre-alpine

# Install wget for health checks
RUN apk add --no-cache wget

WORKDIR /app

# Create non-root user
RUN addgroup -S spring && adduser -S spring -G spring

# Copy jar from build stage
COPY --from=build /app/target/*.jar app.jar

# Copy JWT keys (if they're needed at runtime)
# The keys should already be in the jar from src/main/resources
# But we can also mount them as volume if needed

# Change ownership
RUN chown -R spring:spring /app

USER spring:spring

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8081/actuator/health || exit 1

EXPOSE 8081

# JVM settings optimized for containers
ENTRYPOINT ["java", \
    "-Xms256m", \
    "-Xmx512m", \
    "-XX:+UseContainerSupport", \
    "-XX:MaxRAMPercentage=75.0", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-jar", "app.jar"]