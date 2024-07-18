### Configuration

# set --build-args SKIP_TESTS=true to use
ARG SKIP_TESTS

# --- dos2unix-env    # convert line endings from Windows machines
FROM docker.io/rkimf1/dos2unix@sha256:60f78cd8bf42641afdeae3f947190f98ae293994c0443741a2b3f3034998a6ed as dos2unix-env
WORKDIR /convert
COPY gradlew .
COPY src/test/resources/key/pem/*/*.pem ./
RUN dos2unix ./gradlew *.pem

# --- build-env       # build the SSI Kit
FROM docker.io/gradle:7.5-jdk as build-env

ARG SKIP_TESTS

WORKDIR /appbuild

COPY . /appbuild

# copy converted Windows line endings files
COPY --from=dos2unix-env /convert/gradlew .
COPY --from=dos2unix-env /convert/*.pem src/test/resources/key/

# cache Gradle dependencies
VOLUME /home/gradle/.gradle

RUN if [ -z "$SKIP_TESTS" ]; \
    then echo "* Running full build" && ./gradlew -i clean build installDist; \
    else echo "* Building but skipping tests" && ./gradlew -i clean installDist -x test; \
    fi

# --- opa-env
FROM docker.io/openpolicyagent/opa:0.50.2-static as opa-env

# --- iota-env
FROM docker.io/waltid/waltid_iota_identity_wrapper:latest as iota-env

# --- app-env
FROM docker.io/eclipse-temurin:19 AS app-env

WORKDIR /app

COPY --from=opa-env /opa /usr/local/bin/opa

COPY --from=iota-env /usr/local/lib/libwaltid_iota_identity_wrapper.so /usr/local/lib/libwaltid_iota_identity_wrapper.so
RUN ldconfig

COPY --from=build-env /appbuild/build/install/waltid-ssikit /app/
COPY --from=build-env /appbuild/service-matrix.properties /app/
COPY --from=build-env /appbuild/config /app/config

# Install OpenSSL and create certificates
# Install OpenSSL and create certificates
RUN apt-get update && apt-get install -y openssl \
    && mkdir -p /app/cert/issuer /app/cert/verifier /app/cert/webWallet \
    && openssl req -nodes -x509 -sha256 -newkey rsa:4096 -keyout /app/cert/issuer/issuer.key -out /app/cert/issuer/issuer.crt -days 356 -subj "/C=ES/ST=Murcia/L=Spain/O=walt.id/OU=issuer/CN=umu-issuer" -addext "subjectAltName = DNS:umu-issuer,IP:127.0.0.1" \
    && openssl pkcs12 -export -in /app/cert/issuer/issuer.crt -inkey /app/cert/issuer/issuer.key -out /app/cert/issuer/issuer.p12 -name issuer -passout pass: \
    && openssl req -nodes -x509 -sha256 -newkey rsa:4096 -keyout /app/cert/verifier/verifier.key -out /app/cert/verifier/verifier.crt -days 356 -subj "/C=ES/ST=Murcia/L=Spain/O=walt.id/OU=verifier/CN=umu-verifier" -addext "subjectAltName = DNS:umu-verifier,IP:127.0.0.1" \
    && openssl pkcs12 -export -in /app/cert/verifier/verifier.crt -inkey /app/cert/verifier/verifier.key -out /app/cert/verifier/verifier.p12 -name verifier -passout pass: \
    && openssl req -nodes -x509 -sha256 -newkey rsa:4096 -keyout /app/cert/webWallet/webWallet.key -out /app/cert/webWallet/webWallet.crt -days 356 -subj "/C=ES/ST=Murcia/L=Spain/O=walt.id/OU=webWallet/CN=umu-webWallet" -addext "subjectAltName = DNS:umu-webWallet,IP:127.0.0.1" \
    && openssl pkcs12 -export -in /app/cert/webWallet/webWallet.crt -inkey /app/cert/webWallet/webWallet.key -out /app/cert/webWallet/webWallet.p12 -name webWallet -passout pass:

# Import certificates to Java keystore
RUN keytool -importcert -file /app/cert/issuer/issuer.crt -alias issuer -keystore /opt/java/openjdk/lib/security/cacerts -storepass changeit -noprompt \
    && keytool -importcert -file /app/cert/verifier/verifier.crt -alias verifier -keystore /opt/java/openjdk/lib/security/cacerts -storepass changeit -noprompt \
    && keytool -importcert -file /app/cert/webWallet/webWallet.crt -alias webWallet -keystore /opt/java/openjdk/lib/security/cacerts -storepass changeit -noprompt


### Execution
EXPOSE 7000 7001 7002 7003 7004 7010

ENTRYPOINT ["/app/bin/waltid-ssikit"]
