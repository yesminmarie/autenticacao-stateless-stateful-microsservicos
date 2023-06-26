FROM gradle:7.6.1-alpine as build
WORKDIR /build
COPY . .
RUN gradle build

FROM openjdk:17-alpine
WORKDIR /app
COPY --from=build ./build/build/libs/*.jar ./app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]