package id.walt.services.OIDC_UMU.wallet

import com.google.gson.Gson
import id.walt.cli.WebWalletCommand
import id.walt.services.OIDC_UMU.generarValorAleatorio
import id.walt.services.OIDC_UMU.issuer.Metadata
import id.walt.services.OIDC_UMU.issuer.checkValidMetadata
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

class AuthorizationRequest(
    private val WALLET_PORT: Int,
    private val ENDPOINT_OBTAIN_CREDENTIAL: String,
    private val DID_BACKEND: String
) {

    suspend fun authRequest(
        call: ApplicationCall,
        template: String,
        challenge: String,
        issuerCredentials: WebWalletCommand.IssuerCredentials?,
        ePassport: Boolean,
        metadata: Metadata,
        redirecturi: String? = null
    ){

        val client = HttpClient() {
            install(ContentNegotiation) { json() }
            expectSuccess = false
        }

        val redirect = if (redirecturi != null) ENDPOINT_OBTAIN_CREDENTIAL+"?redirecturi="+redirecturi else ENDPOINT_OBTAIN_CREDENTIAL

        val uri = if (ePassport){
            val jwt = push_ePassport(client, challenge, DID_BACKEND, template,metadata,WALLET_PORT,redirect)
            "http://127.0.0.1:5000/?jwt=$jwt"
        }
        else if (issuerCredentials!=null) {
            push_credential_parameters(client, challenge, issuerCredentials.clientid, template,metadata,WALLET_PORT,redirect)
        } else {
            push_credential_parameters(client, challenge, "", template,metadata,WALLET_PORT,redirect)
        }

        call.respond(uri)
        client.close()
    }

    // Función que finaliza el procesos de obtención del auth token tras comunicarse con el issuer


    /*
        Comienzo del proeceso de emisión de un auth token, devuelve el uri de redirección con la plantilla
        donde se especifican los valores del credential subject necesarios.
    */

    suspend fun push_credential_parameters(client: HttpClient, challenge: String, clientId: String, type: String,metadata: Metadata, WALLET_PORT: Int, ENDPOINT_OBTAIN_CREDENTIAL: String): String {

        println("\n$verde[+] Wallet: PUSH credential parameters request$reset\n")

        if (checkValidMetadata(metadata) ==false) {
            println(rojo + "[!] Error: Error checking metadata values" + reset)
            throw Exception("Error during push credential parameters")
        }

        val responseType = "code"
        val scope = "openid"
        val codeChallengeMethod = "S256"
        val redirectUri = URLEncoder.encode("https://umu-webWallet:$WALLET_PORT/New-Credential", StandardCharsets.UTF_8.name())

        val authorizationDetails = mapOf(
            "type" to "openid_credential",
            "format" to "ldp_vc",
            "credential_definition" to mapOf(
                "type" to listOf("VerifiableCredential", type)
            )
        )

        val authorizationDetailsJson = Gson().toJson(authorizationDetails)
        val authorizationDetailsEncoded = URLEncoder.encode(authorizationDetailsJson, StandardCharsets.UTF_8.name())

        val uri = obtainAuthorizationEndpoint(clientId,metadata.authorizationEndpoint)

        if (uri == null) throw Exception("Error during push credential parameters")

        val url = URLBuilder(uri).apply {
            parameters.append("response_type", responseType)
            parameters.append("scope", scope)
            parameters.append("client_id", clientId)
            parameters.append("code_challenge", challenge)
            parameters.append("code_challenge_method", codeChallengeMethod)
            parameters.append("authorization_details", authorizationDetailsEncoded)
            parameters.append("redirect_uri", ENDPOINT_OBTAIN_CREDENTIAL)
        }.buildString()

        val response: HttpResponse = client.get(url)

        if (response.status == HttpStatusCode.OK) {
            val redirect_uri: String = response.bodyAsText()
            return redirect_uri
        } else {
            println(rojo + "[!] Error: ${response.status.description}" + reset)
            throw Exception("Error during push credential parameters: ${response.status.description}")
        }
    }

    suspend fun push_ePassport(client: HttpClient, challenge: String, clientId: String, type: String, metadata: Metadata, WALLET_PORT: Int, ENDPOINT_OBTAIN_CREDENTIAL: String): String {

        println("\n$verde[+] Wallet: PUSH credential parameters request$reset\n")

        if (checkValidMetadata(metadata) ==false) {
            println(rojo + "[!] Error: Error checking metadata values" + reset)
            throw Exception("Error during push credential parameters")
        }

        val responseType = "code"
        val scope = "openid"
        val codeChallengeMethod = "S256"
        val redirectUri = URLEncoder.encode("https://umu-webWallet:$WALLET_PORT/New-Credential", StandardCharsets.UTF_8.name())

        val authorizationDetails = mapOf(
            "type" to "openid_credential",
            "format" to "ldp_vc",
            "credential_definition" to mapOf(
                "type" to listOf("VerifiableCredential", type)
            )
        )

        val authorizationDetailsJson = Gson().toJson(authorizationDetails)
        val authorizationDetailsEncoded = URLEncoder.encode(authorizationDetailsJson, StandardCharsets.UTF_8.name())

        val uri = obtainAuthorizationEndpoint_ePassport(metadata.authorizationEndpoint)

        if (uri == null) throw Exception("Error during push credential parameters")

        val url = URLBuilder(uri).apply {
            parameters.append("response_type", responseType)
            parameters.append("scope", scope)
            parameters.append("client_id", clientId)
            parameters.append("code_challenge", challenge)
            parameters.append("code_challenge_method", codeChallengeMethod)
            parameters.append("authorization_details", authorizationDetailsEncoded)
            parameters.append("redirect_uri", ENDPOINT_OBTAIN_CREDENTIAL)
        }.buildString()

        val response: HttpResponse = client.get(url)

        if (response.status == HttpStatusCode.OK) {
            val jwt: String = response.bodyAsText()
            return jwt
        } else {
            println(rojo + "[!] Error: ${response.status.description}" + reset)
            throw Exception("Error during push credential parameters: ${response.status.description}")
        }
    }
}
