#!/bin/bash

# Verificación del argumento de la ruta de destino
DEST_DIR=$1

if [ -z "$DEST_DIR" ]; then
  echo "Error: No se ha especificado un directorio de destino."
  echo "Uso: $0 <directorio-destino>"
  exit 1
fi

# Verificación de la existencia del directorio de destino
if [ ! -d "$DEST_DIR" ]; then
  echo "Error: El directorio de destino no existe."
  exit 1
fi

# Copiar los archivos a la ruta de destino especificada
cp -R ./umu-aries-framework-go-main/modules/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts/* "$DEST_DIR/cert.pem"
cp -R ./umu-aries-framework-go-main/modules/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore/* "$DEST_DIR/key"
cp -R ./umu-aries-framework-go-main/modules/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt "$DEST_DIR/ca.crt"

echo "Archivos copiados exitosamente a $DEST_DIR"
