#!/bin/bash

# Asegúrate de que la variable de entorno ISSUER_PORT esté definida
if [ -z "$ISSUER_PORT" ]; then
  echo "Error: La variable de entorno ISSUER_PORT no está definida."
  exit 1
fi

if [ -z "$VERIFIER_PORT" ]; then
  echo "Error: La variable de entorno ISSUER_PORT no está definida."
  exit 1
fi

if [ -z "$WALLET_PORT" ]; then
  echo "Error: La variable de entorno ISSUER_PORT no está definida."
  exit 1
fi


# Directorio raíz para la búsqueda
ROOT_DIR=$1

# Asegúrate de que el directorio raíz esté definido
if [ -z "$ROOT_DIR" ]; then
  echo "Error: No se ha especificado un directorio raíz."
  echo "Uso: $0 <directorio-raíz>"
  exit 1
fi

# Reemplazar <ISSUER_PORT> por el valor de ISSUER_PORT en todos los archivos dentro del directorio raíz y subcarpetas
find "$ROOT_DIR" -type f -exec sed -i "s/<ISSUER_PORT>/$ISSUER_PORT/g" {} +
find "$ROOT_DIR" -type f -exec sed -i "s/<VERIFIER_PORT>/$VERIFIER_PORT/g" {} +
find "$ROOT_DIR" -type f -exec sed -i "s/<WALLET_PORT>/$WALLET_PORT/g" {} +
echo "Reemplazo completado."
