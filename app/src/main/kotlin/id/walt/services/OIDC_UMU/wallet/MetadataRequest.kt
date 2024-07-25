package id.walt.services.OIDC_UMU.wallet

import id.walt.cli.WebWalletCommand
import id.walt.services.OIDC_UMU.issuer.Metadata
import id.walt.services.OIDC_UMU.issuer.fetchMetadataRequest
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.response.*


class MetadataRequest (){
    private val WALLET_PORT = System.getenv("WALLET_PORT").toInt()
    val ENDPOINT_START_PROCESS = "https://wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu/wallet/selectCredential"
    fun getIssuerCredentials(
        call: ApplicationCall
        ): WebWalletCommand.IssuerCredentials? {
        println("\n$verde[+] Wallet: Openid credential offer$reset\n")

        val clientid = call.request.queryParameters["clientid"]
        val clientsecret = call.request.queryParameters["clientsecret"]


        if (clientid != null && clientsecret != null) {
            return WebWalletCommand.IssuerCredentials(clientid,clientsecret)
        } else return null

    }

    suspend fun getCredentialOffer(
        call: ApplicationCall
    ): CredentialOffer? {
        println(4)
        // Extrae el parámetro 'credential_offer_uri' de la solicitud GET
        val credentialOfferUri = call.request.queryParameters["credential_offer_uri"]
        println(5)
        if (credentialOfferUri != null) {
            val client = HttpClient() {
                install(ContentNegotiation) {
                    json()
                }
                expectSuccess = false
            }

            try {
                println(credentialOfferUri)
                val response: HttpResponse = client.get(credentialOfferUri)
                val responseBody = response.bodyAsText()
                println("RESPUESTA 2 :"+responseBody)
                val credentialOffer = parseCredentialOffer(responseBody)
                println(credentialOffer)
                client.close()
                return credentialOffer


            } catch (e: Exception) {
                println("error: "+e)
                client.close()
                call.respondText("Failed to fetch credential offer: ${e.message}", status = HttpStatusCode.InternalServerError)
                return  null
            }


        } else {
            call.respondText("No credential offer URI provided", status = HttpStatusCode.BadRequest)
            return null
        }
    }

    suspend fun getMetadata(
        call: ApplicationCall,
        credentialOffer: CredentialOffer
    ): Metadata {
        val client = HttpClient() {
            install(ContentNegotiation) {
                json()
            }
            expectSuccess = false
        }
        println(9)
        val metadata = fetchMetadataRequest(client,credentialOffer.credential_issuer)
        println(10)
        println(ENDPOINT_START_PROCESS)
        call.respondText(ENDPOINT_START_PROCESS)
        client.close()
        return metadata
    }

}
