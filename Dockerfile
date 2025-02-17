# Use an official OpenJDK runtime as a parent image
FROM eclipse-temurin:21-jdk

# Set the working directory inside the container
WORKDIR /app

# Copy the built JAR file into the container
COPY target/auth-service-*.jar auth-service.jar

# Expose the application's port (matching your Spring Boot app)
EXPOSE 9090

# Command to run the application
ENTRYPOINT ["java", "-jar", "auth-service.jar"]
