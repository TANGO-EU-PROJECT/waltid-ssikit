package id.walt.services.OIDC_UMU.wallet

import com.google.gson.JsonParser
import id.walt.cli.WebWalletCommand
import id.walt.services.OIDC_UMU.issuer.Metadata
import id.walt.services.OIDC_UMU.sha256
import id.walt.services.jwt.WaltIdJwtService
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.*

class CrendentialRequest (
    private val DID_BACKEND: String,
    private val KEY_ALIAS: String
){

    val jwtService = WaltIdJwtService()

    // Partiendo de un auth token obtiene el access token que permite solicitar la emisión de una credencial
    suspend fun accessTokenRequest(
        metadata: Metadata,
        ePassport: Boolean,
        issuerCredentials: WebWalletCommand.IssuerCredentials?,
        authCode: String,
        code: String,
        redirectUri: String


    ): String{
        println("\n$verde[+] Wallet: GET access Token.$reset\n")



        val authHeaderValue = if (ePassport){
            val proof = generateDidProof(authCode)
            "Bearer $proof"
        }
        else if (issuerCredentials == null)
        {
            "Basic $DID_BACKEND"
        }
        else
        {
            val auth = Base64.getEncoder().encodeToString("${issuerCredentials.clientid}:${issuerCredentials.clientsecret}".toByteArray(Charsets.UTF_8))
            "Basic $auth"
        }

        val client = HttpClient() {
            install(ContentNegotiation) { json() }
            expectSuccess = false
        }
        val response = client.post(metadata.tokenEndpoint) {
            header(HttpHeaders.Authorization, authHeaderValue)
            header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)

            setBody(FormDataContent(Parameters.build {
                append("grant_type", "authorization_code")
                append("code", authCode)
                append("code_verifier", code.sha256())
                append("redirect_uri", redirectUri)
            }))
        }

        client.close()
        val token: String = response.bodyAsText()
        return token
    }

    // Comunicación con el endpoint del issuer para solicitar la emisión de la credencial.
    suspend fun credentialRequest(
        metadata: Metadata,
        tokenResponse: String

    ): String{

        println("\n$verde[+] Wallet: GET credential.$reset\n")
        val jsonElement = JsonParser.parseString(tokenResponse)
        if (!jsonElement.isJsonObject) throw IllegalArgumentException("Invalid JSON response")

        val jsonObject = jsonElement.asJsonObject
        val accessToken = jsonObject["access_token"]?.asString ?: throw IllegalArgumentException("Access token not found")
        val cNonce = jsonObject["c_nonce"]?.asString ?: throw IllegalArgumentException("c_nonce not found")
        val signedJWT = generateDidProof(cNonce)

        val client = HttpClient() {
            install(ContentNegotiation) { json() }
            expectSuccess = false
        }
        val response = client.post(metadata.credentialEndpoint!!) {
            header(HttpHeaders.Authorization, "Bearer $accessToken")

            setBody(FormDataContent(Parameters.build {
                append("proof", signedJWT)
            }))
        }
        val credential = response.bodyAsText()
        client.close()
        return credential
    }


    // Generá una prueba de posesión del DID, firmando el nonce proporcionado por el backend

    fun generateDidProof(nonce: String): String {
        val payload = buildJsonObject {
            put("iss", DID_BACKEND)
            put("aud", "https://server.example.com")
            put("c_nonce", nonce)
            put("exp", (System.currentTimeMillis() / 1000))
        }.toString()

        val signedJWT = jwtService.sign(KEY_ALIAS, payload)
        return signedJWT
    }
}
