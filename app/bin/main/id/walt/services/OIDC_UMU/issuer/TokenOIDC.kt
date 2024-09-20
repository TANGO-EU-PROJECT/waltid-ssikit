package id.walt.services.OIDC_UMU.issuer

import id.walt.cli.IssuerCommand
import id.walt.services.jwt.WaltIdJwtService
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import mu.KotlinLogging
import id.walt.services.OIDC_UMU.generarValorAleatorio
import id.walt.services.OIDC_UMU.getValueFromJWT
import id.walt.services.OIDC_UMU.isProofValid
import id.walt.services.OIDC_UMU.wallet.reset
import id.walt.services.OIDC_UMU.wallet.verde
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.*


class TokenOIDC (
    private val DID_BACKEND: String,
    private val KEY_ALIAS: String,
    ) {

    val log = KotlinLogging.logger {}
    val jwtService = WaltIdJwtService()
    suspend fun token(
        call: ApplicationCall,
        clientID: MutableMap<String, IssuerCommand.clientIdValues>,
        authRequestRegistry: MutableMap<String, IssuerCommand.AuthRequest>,
        tokenRegistry: MutableMap<String, IssuerCommand.TokenInfo>,
    ) {

        println("\n$verde[+] Issuer: PUSH OIDC access token request$reset\n")

        val parameters = call.receiveParameters()
        val grantType = parameters["grant_type"]
        val code = parameters["code"]
        val codeVerifier = parameters["code_verifier"]
        val redirectUri = parameters["redirect_uri"]
        val authorizationHeader = call.request.headers["Authorization"]





        if (grantType.isNullOrEmpty() || code.isNullOrEmpty() || codeVerifier.isNullOrEmpty() || redirectUri.isNullOrEmpty() || authorizationHeader.isNullOrEmpty()) {
            call.respond(HttpStatusCode.BadRequest, "Missing required parameters")
        }


        var proof = ""
        val clientid =
            if (authorizationHeader!!.startsWith("Basic"))
                {
                    var clientId = ""
                    var clientSecret = ""
                    val auth = authorizationHeader.removePrefix("Basic ")
                    val decodedCredentials = decodeBasicAuth(auth)
                    if (decodedCredentials != null){
                        clientId = decodedCredentials.first
                        clientSecret = decodedCredentials.second
                    }else{
                        call.respond(HttpStatusCode.Unauthorized, "Invalid client credentials")
                    }
                    if (!clientID.containsKey(clientId) || clientID[clientId]!!.clientsecret  != clientSecret) {
                        call.respond(HttpStatusCode.Unauthorized, "Invalid client credentials")
                    }
                    clientId

                }
            else if (authorizationHeader.startsWith("Bearer"))
            {
                proof = authorizationHeader.removePrefix("Bearer ")
                getValueFromJWT(proof, "iss")
            }
            else {
                call.respond(HttpStatusCode.Unauthorized, "Invalid client credentials")
                "Error"
            }


        val authRequestInfo = authRequestRegistry[clientid] ?: throw IllegalArgumentException("The clientId isn't valid.")

        if (authRequestInfo.authType == IssuerCommand.AuthType.EPASSPORT)
        {

            if (code == null || isProofValid(proof,code,"c_nonce") == false) {
                call.respond(HttpStatusCode.Unauthorized, "Invalid Bearer token")
            }

        }


        if (!(authRequestInfo.code == code && authRequestInfo.codeVerifier == codeVerifier))
        {
            call.respond(HttpStatusCode.BadRequest, "Invalid code or code_verifier")
        }

        if(isTokenExpired(authRequestInfo)){
            call.respond(HttpStatusCode.Unauthorized, "Auth token is expired")
        }

        val accessToken = accessTokenResponse(clientid, authRequestInfo.credentialtype, tokenRegistry)

        log.debug { "token -> [!] Issuer logs: accessToken - ${accessToken}" }.toString()

        call.respond(accessToken)
    }

    // Decodificación de la cabecera de autenticacion en el endpoint de generación del access token
    fun decodeBasicAuth(authHeader: String): Pair<String, String>? {
        val credentials = String(Base64.getDecoder().decode(authHeader), Charsets.UTF_8)
        val clientIdSecret = credentials.split(":")
        return Pair(clientIdSecret[0], clientIdSecret[1])
    }


    // Comprueba que el auth token no se encuentre expirado
    fun isTokenExpired(authRequest: IssuerCommand.AuthRequest): Boolean {

        val currentTime = Instant.now()
        if (authRequest.expiration.isBefore(currentTime)) return true
        return false
    }

    // Función encargada de devolver un accessToken con el tipo de credencial que se desea emitir.
    fun accessTokenResponse(clientId: String, type: String, tokenRegistry: MutableMap<String, IssuerCommand.TokenInfo>):String{
        val payload = buildJsonObject {
            put("iss", DID_BACKEND)
            put("client_id", clientId)
            put("exp", (System.currentTimeMillis() / 1000) + 60)
        }.toString()

        val list: List<String> = listOf("VerifiableId", type)

        val bearer = jwtService.sign(KEY_ALIAS, payload)
        val nonce = generarValorAleatorio()

        val responseJson = buildJsonObject {
            put("access_token", bearer)
            put("token_type", "bearer")
            put("expires_in", 60)
            put("c_nonce", nonce)
            put("c_nonce_expires_in", 60)
            putJsonArray("authorization_details") {
                add(buildJsonObject {
                    put("type", "openid_credential")
                    put("format", "jwt_vc_json")
                    put("credential_definition", buildJsonObject {
                        putJsonArray("type") {
                            list.forEach { type ->
                                add(type)
                            }
                        }
                    })
                    putJsonArray("credential_identifiers") {
                        add("CivilEngineeringDegree-2023")
                        add("ElectricalEngineeringDegree-2023")
                    }
                })
            }
        }
        val expirationTime = Instant.now().plusSeconds(60)
        tokenRegistry[clientId] = IssuerCommand.TokenInfo(bearer, nonce, expirationTime)
        return responseJson.toString()
    }


}
