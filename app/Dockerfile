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

RUN ./gradlew -i clean installDist -x test 

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

# Install OpenSSL and create certificates
#RUN apt-get update && apt-get install -y openssl \
#    && mkdir -p /app/cert/ \
#    && openssl req -nodes -x509 -sha256 -newkey rsa:4096 -keyout /app/cert/cert.key -out /app/cert/cert.crt -days 356 -subj "/C=ES/ST=Murcia/L=Spain/O=walt.id/OU=issuer/CN=waltid" -addext "subjectAltName = DNS:wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu,IP:127.0.0.1" \
#    && openssl pkcs12 -export -in /app/cert/cert.crt -inkey /app/cert/cert.key -out /app/cert/cert.p12 -name cert -passout pass: \

COPY --from=build-env /appbuild/ /app/

# Import certificates to Java keystore
RUN keytool -importcert -file /app/cert/cert.crt -alias cert -keystore /opt/java/openjdk/lib/security/cacerts -storepass changeit -noprompt 

ENV ISSUER_PORT=30000
ENV VERIFIER_PORT=30001
ENV WALLET_PORT=30002
ENV MODE=Default
ENV LOCAL=true


CMD /app/ssikit.sh fullApi