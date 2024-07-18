# Modificación de la Herramienta SSIKIT

Este proyecto modifica la herramienta de SSIKIT para desplegar los siguientes componentes:

- Issuer
- Verifier
- Web Wallet

## Instalación

Sigue los pasos a continuación para configurar el entorno necesario para utilizar los componentes del proyecto.

### Configuración de Hosts

Modifica el archivo `/etc/hosts` para añadir las siguientes rutas como localhost:

```
127.0.0.1 localhost umu-issuer umu-webWallet umu-verifier
```

### Importación de Certificados para HTTPS

La carpeta `/cert` contiene 3 directorios para importar el certificado de cada componente.

#### Importación al JDK:

Ejecuta el siguiente comando para importar los certificados al JDK:

```bash
sudo keytool -import -alias <NAME> -file <NAME>.crt -keystore /usr/lib/jvm/<TU_VERSION>/lib/security/cacerts -storepass changeit
```

- Nombre del verifier -> `verifier`
- Nombre del issuer -> `issuer`
- Nombre del web wallet -> `webWallet`

#### Importación al Navegador:

Debes añadir los 3 certificados dentro del listado de certificados confiables de tu navegador.

#### Importación Manual:

Dado que son certificados autofirmados, debes confiar manualmente en ellos accediendo a los siguientes sitios web:

- [https://umu-issuer:8443](https://umu-issuer:8443)
- [https://umu-verifier:8444](https://umu-verifier:8444)
- [https://umu-webWallet:8445](https://umu-webWallet:8445)

### Instalación de OPA para la Gestión de Políticas

Instala OPA para gestionar las políticas de seguridad con el siguiente comando:

```bash
curl -L -o opa https://openpolicyagent.org/downloads/v0.62.1/opa_linux_amd64_static
chmod 755 ./opa
mv opa /usr/bin
```

### HYPERLEDGER

La versión actual esta pensada para utilizar una blockchain de `hyperledger fabric` en la que subir y consultar los dids. En caso de no querer esto se debe modificar la variable global `local` en `verifierServer.kt` y `issuerServer.kt`.

```bash
var local = true
```

### USO

Para ver los comandos con sus opciones:

```bash
./ssikit.sh --help
```

Levantar todos los servicios `(issuer, verifier y web wallet)`

```bash
./ssikit fullpi
```

