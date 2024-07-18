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

object VDR {
    private const val CHANNEL_NAME = "mychannel"
    private const val CHAINCODE_NAME = "sacc"
    private const val MSP_ID = "Org1MSP"
    private val currentDirectory = System.getProperty("user.dir")
    private val CERT_PATH = Paths.get(currentDirectory, "src/main/kotlin/id/walt/services/ecosystems/fabric/resources/cert.pem")
    private val KEY_DIR_PATH = Paths.get(currentDirectory, "src/main/kotlin/id/walt/services/ecosystems/fabric/resources/key")
    private val TLS_CERT_PATH = Paths.get(currentDirectory, "src/main/kotlin/id/walt/services/ecosystems/fabric/resources/ca.crt")
    private val PEER_ENDPOINT = System.getenv("PEER_ENDPOINT") ?: "127.0.0.1"
    private const val OVERRIDE_AUTH = "peer0.org1.example.com"

    private fun getGateway(): Gateway {
        val sslContext = GrpcSslContexts.forClient().trustManager(TLS_CERT_PATH.toFile()).build()
        val channel = NettyChannelBuilder.forAddress(PEER_ENDPOINT, 7051)
            .overrideAuthority(OVERRIDE_AUTH)
            .sslContext(sslContext)
            .useTransportSecurity()
            .build()
        return Gateway.newInstance()
            .identity(newIdentity())
            .signer(newSigner())
            .connection(channel)
            .apply {
                evaluateOptions { it.withDeadlineAfter(5, TimeUnit.SECONDS) }
                endorseOptions { it.withDeadlineAfter(15, TimeUnit.SECONDS) }
                submitOptions { it.withDeadlineAfter(5, TimeUnit.SECONDS) }
                commitStatusOptions { it.withDeadlineAfter(1, TimeUnit.MINUTES) }
            }
            .connect().also {
                Runtime.getRuntime().addShutdownHook(Thread {
                    it.close()
                    channel.shutdown()
                    if (!channel.awaitTermination(1, TimeUnit.MINUTES)) {
                        println("Failed to close the channel properly")
                    }
                })
            }
    }

    private fun performAction(action: (Contract) -> String): String? {
        getGateway().use { gateway ->
            val network = gateway.getNetwork(CHANNEL_NAME)
            val contract = network.getContract(CHAINCODE_NAME)
            return action(contract)
        } // Gateway and associated resources are automatically closed here
    }

    fun setValue(key: String, value: String) {
        println("IP: "+PEER_ENDPOINT)
        try {
            val result = performAction {
                it.submitTransaction("set", key, value)
                "Transaction submitted successfully"
            }
            println(result)
        } catch (e: Exception) {
            println("Error setting value: ${e.message}")
        }
    }

    fun getValue(key: String): String? {
        return try {
            performAction { String(it.evaluateTransaction("get", key)) }
        } catch (e: Exception) {
            println("Error getting value: ${e.message}")
            null
        }
    }
    @Throws(IOException::class, CertificateException::class)
    private fun newIdentity(): Identity {
        Files.newBufferedReader(CERT_PATH).use { reader ->
            return X509Identity(MSP_ID, Identities.readX509Certificate(reader))
        }
    }

    @Throws(IOException::class, InvalidKeyException::class)
    private fun newSigner(): Signer {
        Files.newBufferedReader(KEY_DIR_PATH).use { reader ->
            return Signers.newPrivateKeySigner(Identities.readPrivateKey(reader))
        }
    }
}
