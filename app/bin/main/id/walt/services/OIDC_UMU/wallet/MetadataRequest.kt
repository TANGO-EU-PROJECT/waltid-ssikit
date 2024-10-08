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

private val URI_DSC = System.getenv("URI")

class MetadataRequest (){
    private val WALLET_PORT = System.getenv("WALLET_PORT").toInt()
    val ENDPOINT_START_PROCESS = "https://$URI_DSC/wallet/selectCredential"
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
        // Extrae el parámetro 'credential_offer_uri' de la solicitud GET
        val credentialOfferUri = call.request.queryParameters["credential_offer_uri"]
        if (credentialOfferUri != null) {
            val client = HttpClient() {
                install(ContentNegotiation) {
                    json()
                }
                expectSuccess = false
            }

            try {
                val response: HttpResponse = client.get(credentialOfferUri)
                val responseBody = response.bodyAsText()
                val credentialOffer = parseCredentialOffer(responseBody)
                client.close()
                return credentialOffer


            } catch (e: Exception) {
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
        val metadata = fetchMetadataRequest(client,credentialOffer.credential_issuer)
        call.respondText(ENDPOINT_START_PROCESS)
        client.close()
        return metadata
    }

}
