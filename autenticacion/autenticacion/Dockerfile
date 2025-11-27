FROM openjdk:17-jdk-slim
ARG JAR_FILE=target/autenticacion-0.0.1-SNAPSHOT.jar
COPY ${JAR_FILE} tienda_videojuegos.jar
EXPOSE 8081
ENTRYPOINT ["java","-jar","/tienda_videojuegos.jar"]