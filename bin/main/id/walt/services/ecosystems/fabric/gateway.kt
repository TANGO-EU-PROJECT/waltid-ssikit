package id.walt.services.ecosystems.fabric

import org.hyperledger.fabric.client.Contract
import org.hyperledger.fabric.client.Gateway
import io.grpc.ManagedChannel
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import org.hyperledger.fabric.client.identity.*
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Paths
import java.security.InvalidKeyException
import java.security.cert.CertificateException
import java.util.concurrent.TimeUnit

import id.walt.services.ecosystems.fabric.ObtenerGateway

object VDR {
    private val CHANNEL_NAME = "mychannel"
    private val CHAINCODE_NAME = "sacc"
    private lateinit var contract: Contract
    private lateinit var gateway: Gateway

    val MSP_ID = "Org1MSP"

    val currentDirectory = System.getProperty("user.dir")

    // RUTA A UN CERTIFICADO DE USUARIO
    val CERT_PATH = Paths.get(currentDirectory,"src/main/kotlin/id/walt/services/ecosystems/fabric/resources/cert.pem")

    // RUTA A LA CLAVE DEL ANTERIOR CERTIFICADO
    val KEY_DIR_PATH = Paths.get(currentDirectory,"src/main/kotlin/id/walt/services/ecosystems/fabric/resources/key")


    // RUTA AL CERTIFICADO EMITIDO POR LA CA PARA LA COMUNICACIÓN TLS
    val TLS_CERT_PATH = Paths.get(currentDirectory,"src/main/kotlin/id/walt/services/ecosystems/fabric/resources/ca.crt")

    val PEER_ENDPOINT = "localhost"
    val OVERRIDE_AUTH = "peer0.org1.example.com"



    @Throws(IOException::class)
    private fun newGrpcConnection(): ManagedChannel {
        //val credentials = TlsChannelCredentials.newBuilder()
        try {
            val ssl: io.grpc.netty.shaded.io.netty.handler.ssl.SslContext? = GrpcSslContexts.forClient()
                .trustManager(TLS_CERT_PATH.toFile())
                .build();
            val builder: NettyChannelBuilder = NettyChannelBuilder.forAddress(PEER_ENDPOINT,7051)
            builder.overrideAuthority(OVERRIDE_AUTH)
            builder.useTransportSecurity()
            builder.sslContext(ssl)

            return builder.build()
        }catch (e: Exception) {
            throw RuntimeException("Couldn't set up SSL context", e)
        }


    }

    @Throws(IOException::class, CertificateException::class)
    private fun newIdentity(): Identity {
        val certReader = Files.newBufferedReader(CERT_PATH)
        val certificate = Identities.readX509Certificate(certReader)

        return X509Identity(MSP_ID, certificate)
    }

    @Throws(IOException::class, InvalidKeyException::class)
    private fun newSigner(): Signer {
        val keyReader = Files.newBufferedReader(KEY_DIR_PATH)
        val privateKey = Identities.readPrivateKey(keyReader)

        return Signers.newPrivateKeySigner(privateKey)
    }

    fun getGateway(): Gateway {
        // La conexión gRPC del cliente debe ser compartida por todas las conexiones de Gateway a este punto final.
        val channel: ManagedChannel = newGrpcConnection()

        val builder: Gateway.Builder = Gateway.newInstance()
            .identity(newIdentity())
            .signer(newSigner())
            .connection(channel)
            // Tiempos de espera predeterminados para diferentes llamadas gRPC
            .evaluateOptions { it.withDeadlineAfter(5, TimeUnit.SECONDS) }
            .endorseOptions { it.withDeadlineAfter(15, TimeUnit.SECONDS) }
            .submitOptions { it.withDeadlineAfter(5, TimeUnit.SECONDS) }
            .commitStatusOptions { it.withDeadlineAfter(1, TimeUnit.MINUTES) }


        return builder.connect()


    }

    fun initialize() {
        this.gateway = getGateway()
        val network = gateway.getNetwork(CHANNEL_NAME)
        contract = network.getContract(CHAINCODE_NAME)
    }

    // Función para subir un valor de prueba al smart contract
    fun setValue(key: String, value: String) {
        try {
            println("\n--> Submit Transaction: Set, key: $key, value: $value")
            contract.submitTransaction("set", key, value)
            println("*** Transaction committed successfully")
        } catch (e: Exception) {
            println("Error setting value: ${e.message}")
        }
    }

    // Función para consultar un valor del smart contract
    fun getValue(key: String): String? {
        try {
            println("\n--> Evaluate Transaction: Get, key: $key")
            val resultBytes = contract.evaluateTransaction("get", key)
            val result = String(resultBytes)
            println("Result: $result")
            return result
        } catch (e: Exception) {
            println("Error getting value: ${e.message}")
            return null
        }
    }
}
