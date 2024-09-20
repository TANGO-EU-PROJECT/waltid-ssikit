package id.walt.services.ecosystems.fabric

import io.grpc.ManagedChannel
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder
import org.hyperledger.fabric.client.Gateway
import org.hyperledger.fabric.client.identity.*
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Paths
import java.security.InvalidKeyException
import java.security.cert.CertificateException
import java.util.concurrent.TimeUnit


class ObtenerGateway(){

    val MSP_ID = "Org1MSP"

    val currentDirectory = System.getProperty("user.dir")

    val PEER_ENDPOINT = System.getenv("PEER_ENDPOINT") ?: "127.0.0.1"

    val OVERRIDE_AUTH = "peer0.org1.example.com"



    @Throws(IOException::class)
    private fun newGrpcConnection(): ManagedChannel {
        // RUTA AL CERTIFICADO EMITIDO POR LA CA PARA LA COMUNICACIÓN TLS
        val TLS_CERT_PATH = Paths.get(currentDirectory,"./resources/ca.crt")
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
        // RUTA A UN CERTIFICADO DE USUARIO
        val CERT_PATH = Paths.get("./resources/cert.pem")

        val certReader = Files.newBufferedReader(CERT_PATH)
        val certificate = Identities.readX509Certificate(certReader)

        return X509Identity(MSP_ID, certificate)
    }

    @Throws(IOException::class, InvalidKeyException::class)
    private fun newSigner(): Signer {
        // RUTA A LA CLAVE DEL ANTERIOR CERTIFICADO
        val KEY_DIR_PATH = Paths.get(currentDirectory,"./resources/key")
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

}




