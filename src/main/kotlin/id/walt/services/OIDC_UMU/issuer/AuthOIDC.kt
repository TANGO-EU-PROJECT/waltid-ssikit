package id.walt.services.OIDC_UMU.issuer

import com.google.gson.Gson
import com.google.gson.JsonObject
import id.walt.cli.IssuerCommand
import id.walt.services.OIDC_UMU.generarValorAleatorio
import id.walt.services.OIDC_UMU.sha256
import id.walt.services.OIDC_UMU.wallet.reset
import id.walt.services.OIDC_UMU.wallet.rojo
import id.walt.services.OIDC_UMU.wallet.verde
import id.walt.services.jwt.WaltIdJwtService
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import kotlinx.serialization.json.*
import mu.KotlinLogging

class AuthOIDC(
    private val DID_BACKEND: String,
    private val KEY_ALIAS: String,
) {

    private val ISSUER_PORT = System.getenv("ISSUER_PORT").toInt()
    val log = KotlinLogging.logger {}
    val jwtService = WaltIdJwtService()
    suspend fun auth(call: ApplicationCall, clientID:  MutableMap<String, IssuerCommand.clientIdValues>, authRequestRegistry: MutableMap <String, IssuerCommand.AuthRequest>){
        println("\n$verde[+] Issuer: PUSH OIDC auth request$reset\n")

        try {
            val responseType = call.parameters["response_type"]
            val clientId = call.parameters["client_id"]
            val codeChallenge = call.parameters["code_challenge"]
            val codeChallengeMethod = call.parameters["code_challenge_method"]
            val authorizationDetailsJson = call.parameters["authorization_details"]
            val redirectUri = call.parameters["redirect_uri"]
            if (responseType.isNullOrEmpty() || clientId.isNullOrEmpty() ||
                codeChallenge.isNullOrEmpty() || codeChallengeMethod.isNullOrEmpty() ||
                authorizationDetailsJson.isNullOrEmpty() || redirectUri.isNullOrEmpty()) {
                throw IllegalArgumentException("Missing required parameters.")
            }

            val authDetailsJson = URLDecoder.decode(authorizationDetailsJson, StandardCharsets.UTF_8.name())
            val authDetails = Gson().fromJson(authDetailsJson, Map::class.java)

            val type = authDetails["type"] ?: throw IllegalArgumentException("Missing 'type' in 'authorization_details'.")
            val format = authDetails["format"] ?: throw IllegalArgumentException("Missing 'format' in 'authorization_details'.")

            if (!clientID.containsKey(clientId)) throw IllegalArgumentException("The clientID isn't valid.")


            if (type != "openid_credential") throw IllegalArgumentException("The type isn't valid.")
            if (format != "ldp_vc") throw IllegalArgumentException("The format isn't valid.")
            if (responseType != "code") throw IllegalArgumentException("The responseType isn't valid.")

            val credentialDefinition = authDetails["credential_definition"] as? Map<*, *> ?: throw IllegalArgumentException("Missing 'credential_definition' in 'authorization_details'.")
            val typesRaw = credentialDefinition["type"] as? List<*> ?: throw IllegalArgumentException("Missing 'type' in 'credential_definition'.")
            val types = typesRaw.filterIsInstance<String>()
            val t = types?.find { it.toString() != "VerifiableCredential" }
            if (t == null) {
                throw IllegalArgumentException("Invalid credential type (/auth).")
            }

            // Genera el código para el auth token
            val code = generarValorAleatorio()
            // Registra el token, a falta de especificar los atributos del credential subject
            authRequestRegistry[clientId] = IssuerCommand.AuthRequest(
                codeChallenge.sha256(),
                code,
                t,
                mutableMapOf<String, Any>(),
                redirecUri = redirectUri,
                authType = IssuerCommand.AuthType.NORMAL
            )

            // Url con los atributos del credential subject
            val locationUri = StringBuilder()
            locationUri.append("https://umu-issuer:"+ISSUER_PORT+"/form")
            locationUri.append("?clientId=$clientId")
            locationUri.append("&template=$t")

            log.debug { "auth -> [!] Issuer logs: locationUri - ${locationUri}" }.toString()

            call.respond(locationUri.toString())

        } catch (e: IllegalArgumentException) {
            // Responder con un error si falta algún parámetro o si los valores no son válidos
            println(rojo + "[!] Error: ${e.message}" + reset)
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to e.message))
        } catch (e: Exception) {
            // Capturar cualquier otro error inesperado
            println(rojo + "[!] Unexpected Error: ${e.localizedMessage}" + reset)
            call.respond(HttpStatusCode.InternalServerError, mapOf("error" to "An unexpected error occurred."))
        }
    }

    suspend fun auth_late(call: ApplicationCall, clientID:  MutableMap<String, IssuerCommand.clientIdValues>, authRequestRegistry: MutableMap <String, IssuerCommand.AuthRequest>){
        println("\n$verde[+] Issuer: PUSH OIDC auth-late request$reset\n")

        try {
            val responseType = call.parameters["response_type"]
            val codeChallenge = call.parameters["code_challenge"]
            val codeChallengeMethod = call.parameters["code_challenge_method"]
            val authorizationDetailsJson = call.parameters["authorization_details"]
            val redirectUri = call.parameters["redirect_uri"]

            if (responseType.isNullOrEmpty() ||
                codeChallenge.isNullOrEmpty() || codeChallengeMethod.isNullOrEmpty() ||
                authorizationDetailsJson.isNullOrEmpty() || redirectUri.isNullOrEmpty()) {
                throw IllegalArgumentException("Missing required parameters.")
            }

            val authDetailsJson = URLDecoder.decode(authorizationDetailsJson, StandardCharsets.UTF_8.name())
            val authDetails = Gson().fromJson(authDetailsJson, Map::class.java)

            val type = authDetails["type"] ?: throw IllegalArgumentException("Missing 'type' in 'authorization_details'.")
            val format = authDetails["format"] ?: throw IllegalArgumentException("Missing 'format' in 'authorization_details'.")


            if (type != "openid_credential") throw IllegalArgumentException("The type isn't valid.")
            if (format != "ldp_vc") throw IllegalArgumentException("The format isn't valid.")
            if (responseType != "code") throw IllegalArgumentException("The responseType isn't valid.")

            val credentialDefinition = authDetails["credential_definition"] as? Map<*, *> ?: throw IllegalArgumentException("Missing 'credential_definition' in 'authorization_details'.")
            val typesRaw = credentialDefinition["type"] as? List<*> ?: throw IllegalArgumentException("Missing 'type' in 'credential_definition'.")
            val types = typesRaw.filterIsInstance<String>()
            val t = types?.find { it.toString() != "VerifiableCredential" }
            if (t == null) {
                throw IllegalArgumentException("Invalid credential type (/auth).")
            }

            // Genera el código para el auth token
            val code = generarValorAleatorio()
            val state = generarValorAleatorio()
            // Registra el token, a falta de especificar los atributos del credential subject
            authRequestRegistry[state] = IssuerCommand.AuthRequest(
                codeChallenge.sha256(),
                code,
                t,
                mutableMapOf<String, Any>(),
                redirecUri = redirectUri,
                authType = IssuerCommand.AuthType.LATE
            )

            // Url con los atributos del credential subject
            val locationUri = StringBuilder()
            locationUri.append("https://umu-issuer:"+ISSUER_PORT+"/auth-late/form")
            locationUri.append("?state=$state")
            locationUri.append("&template=$t")

            log.debug { "auth -> [!] Issuer logs: locationUri - ${locationUri}" }.toString()

            call.respond(locationUri.toString())

        } catch (e: IllegalArgumentException) {
            // Responder con un error si falta algún parámetro o si los valores no son válidos
            println(rojo + "[!] Error: ${e.message}" + reset)
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to e.message))
        } catch (e: Exception) {
            // Capturar cualquier otro error inesperado
            println(rojo + "[!] Unexpected Error: ${e.localizedMessage}" + reset)
            call.respond(HttpStatusCode.InternalServerError, mapOf("error" to "An unexpected error occurred."))
        }
    }

    suspend fun auth_ePassport(call: ApplicationCall, clientID:  MutableMap<String, IssuerCommand.clientIdValues>, authRequestRegistry: MutableMap <String, IssuerCommand.AuthRequest>){
        println("\n$verde[+] Issuer: PUSH OIDC auth-ePassport request$reset\n")

        try {
            val responseType = call.parameters["response_type"]
            val clientId = call.parameters["client_id"]
            val codeChallenge = call.parameters["code_challenge"]
            val codeChallengeMethod = call.parameters["code_challenge_method"]
            val authorizationDetailsJson = call.parameters["authorization_details"]
            val redirectUri = call.parameters["redirect_uri"]

            if (responseType.isNullOrEmpty() || clientId.isNullOrEmpty() ||
                codeChallenge.isNullOrEmpty() || codeChallengeMethod.isNullOrEmpty() ||
                authorizationDetailsJson.isNullOrEmpty() || redirectUri.isNullOrEmpty()) {
                throw IllegalArgumentException("Missing required parameters.")
            }

            val authDetailsJson = URLDecoder.decode(authorizationDetailsJson, StandardCharsets.UTF_8.name())
            val authDetails = Gson().fromJson(authDetailsJson, Map::class.java)

            val type = authDetails["type"] ?: throw IllegalArgumentException("Missing 'type' in 'authorization_details'.")
            val format = authDetails["format"] ?: throw IllegalArgumentException("Missing 'format' in 'authorization_details'.")

            if (!clientId.startsWith("did:")) throw IllegalArgumentException("The clientID isn't valid.")
            val state = generarValorAleatorio()


            if (type != "openid_credential") throw IllegalArgumentException("The type isn't valid.")
            if (format != "ldp_vc") throw IllegalArgumentException("The format isn't valid.")
            if (responseType != "code") throw IllegalArgumentException("The responseType isn't valid.")

            val credentialDefinition = authDetails["credential_definition"] as? Map<*, *> ?: throw IllegalArgumentException("Missing 'credential_definition' in 'authorization_details'.")
            val typesRaw = credentialDefinition["type"] as? List<*> ?: throw IllegalArgumentException("Missing 'type' in 'credential_definition'.")
            val types = typesRaw.filterIsInstance<String>()
            val t = types?.find { it.toString() != "VerifiableCredential" }
            if (t == null) {
                throw IllegalArgumentException("Invalid credential type (/auth).")
            }

            // Genera el código para el auth token
            val code = generarValorAleatorio()
            // Registra el token, a falta de especificar los atributos del credential subject
            authRequestRegistry[state] = IssuerCommand.AuthRequest(
                codeChallenge.sha256(),
                code,
                t,
                mutableMapOf<String, Any>(),
                redirecUri = redirectUri,
                authType = IssuerCommand.AuthType.EPASSPORT,
                clientId = clientId
            )

            call.respond(authInfoResponse(clientId,state))

        } catch (e: IllegalArgumentException) {
            // Responder con un error si falta algún parámetro o si los valores no son válidos
            println(rojo + "[!] Error: ${e.message}" + reset)
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to e.message))
        } catch (e: Exception) {
            // Capturar cualquier otro error inesperado
            println(rojo + "[!] Unexpected Error: ${e.localizedMessage}" + reset)
            call.respond(HttpStatusCode.InternalServerError, mapOf("error" to "An unexpected error occurred."))
        }
    }

    suspend fun code(call: ApplicationCall, clientID:  MutableMap<String, IssuerCommand.clientIdValues>, authRequestRegistry: MutableMap <String, IssuerCommand.AuthRequest>){
        println("\n$verde[+] Issuer: POST /Code request$reset\n")

        try {
            val receivedContent = call.receiveText()
            val json = Json.parseToJsonElement(receivedContent).jsonObject
            val clientId = json["clientId"]?.toString()?.removeSurrounding("\"") ?: throw IllegalArgumentException("clientID not found")
            val template = json["template"]?.toString()?.removeSurrounding("\"") ?: throw IllegalArgumentException("template not found")


            if (clientId.isNullOrEmpty() || template.isNullOrEmpty()) {
                throw IllegalArgumentException("Missing required parameters.")
            }

            val gson = Gson()
            val templateJson = gson.fromJson(template, JsonObject::class.java)
            val credentialSubjectMap = mutableMapOf<String, Any>()
            templateJson.entrySet().forEach { entry ->
                val key = entry.key
                val value = entry.value.asString
                credentialSubjectMap[key] = value
            }

            if (!clientID.containsKey(clientId)) throw IllegalArgumentException("The clientID isn't valid.")

            val authRequest = authRequestRegistry[clientId] ?: throw IllegalArgumentException("The clientId isn't valid.")

            if (authRequest.authType != IssuerCommand.AuthType.NORMAL) throw IllegalArgumentException("Error in the process")

            authRequestRegistry[clientId] = IssuerCommand.AuthRequest(
                authRequest.codeVerifier,
                authRequest.code,
                authRequest.credentialtype,
                credentialSubjectMap,
                authRequest.expiration,
                redirecUri = authRequest.redirecUri,
                authType = authRequest.authType
            )

            log.debug { "authCode -> [!] Issuer logs: authRequest - ${authRequest.code}" }.toString()
            val locationUri = StringBuilder()
            locationUri.append(authRequest.redirecUri)
            val firstChart = if (authRequest.redirecUri.contains("?")) "&" else "?"
            locationUri.append("${firstChart}code=${authRequest.code}")
            call.respond(locationUri.toString())
        } catch (e: IllegalArgumentException) {
            println("$rojo[!] Error: ${e.message}$reset")
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to e.message))
        } catch (e: Exception) {
            println("$rojo[!] Unexpected Error: ${e.localizedMessage}$reset")
            call.respond(HttpStatusCode.InternalServerError, mapOf("error" to "An unexpected error occurred."))
        }
    }
    suspend fun code_late(call: ApplicationCall, clientID:  MutableMap<String, IssuerCommand.clientIdValues>, authRequestRegistry: MutableMap <String, IssuerCommand.AuthRequest>){
        println("\n$verde[+] Issuer: POST /Code-late request$reset\n")

        try {
            val receivedContent = call.receiveText()
            val json = Json.parseToJsonElement(receivedContent).jsonObject
            val clientId = json["clientId"]?.toString()?.removeSurrounding("\"") ?: throw IllegalArgumentException("clientID not found")
            val template = json["template"]?.toString()?.removeSurrounding("\"") ?: throw IllegalArgumentException("template not found")
            val state = json["state"]?.toString()?.removeSurrounding("\"")

            if (clientId.isNullOrEmpty() || template.isNullOrEmpty()) {
                throw IllegalArgumentException("Missing required parameters.")
            }

            val gson = Gson()
            val templateJson = gson.fromJson(template, JsonObject::class.java)
            val credentialSubjectMap = mutableMapOf<String, Any>()
            templateJson.entrySet().forEach { entry ->
                val key = entry.key
                val value = entry.value.asString
                credentialSubjectMap[key] = value
            }

            if (!clientID.containsKey(clientId)) throw IllegalArgumentException("The clientID isn't valid.")

            val authRequest = authRequestRegistry.remove(state) ?: throw IllegalArgumentException("The state isn't valid.")

            if (authRequest.authType != IssuerCommand.AuthType.LATE) throw IllegalArgumentException("Error in the process")

            authRequestRegistry[clientId] = IssuerCommand.AuthRequest(
                authRequest.codeVerifier,
                authRequest.code,
                authRequest.credentialtype,
                credentialSubjectMap,
                authRequest.expiration,
                redirecUri = authRequest.redirecUri,
                authType = authRequest.authType
            )

            log.debug { "authCode -> [!] Issuer logs: authRequest - ${authRequest.code}" }.toString()
            val locationUri = StringBuilder()
            locationUri.append(authRequest.redirecUri)
            val firstChart = if (authRequest.redirecUri.contains("?")) "&" else "?"
            locationUri.append("${firstChart}code=${authRequest.code}&clientid=${clientId}&clientsecret=${clientID[clientId]!!.clientsecret}")
            call.respond(locationUri.toString())
        } catch (e: IllegalArgumentException) {
            println("$rojo[!] Error: ${e.message}$reset")
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to e.message))
        } catch (e: Exception) {
            println("$rojo[!] Unexpected Error: ${e.localizedMessage}$reset")
            call.respond(HttpStatusCode.InternalServerError, mapOf("error" to "An unexpected error occurred."))
        }
    }
    suspend fun code_ePassport(call: ApplicationCall, clientID:  MutableMap<String, IssuerCommand.clientIdValues>, authRequestRegistry: MutableMap <String, IssuerCommand.AuthRequest>){
        println("\n$verde[+] Issuer: POST /Code-ePassport request$reset\n")

        try {
            val receivedContent = call.receiveText()
            val json = Json.parseToJsonElement(receivedContent).jsonObject
            val clientId = json["clientId"]?.toString()?.removeSurrounding("\"") ?: throw IllegalArgumentException("clientID not found")
            val template = json["template"]?.toString()?.removeSurrounding("\"") ?: throw IllegalArgumentException("template not found")
            val state = json["state"]?.toString()?.removeSurrounding("\"") ?: throw IllegalArgumentException("template not found")

            if (clientId.isNullOrEmpty() || template.isNullOrEmpty() || state.isNullOrEmpty()) {
                throw IllegalArgumentException("Missing required parameters.")
            }

            val gson = Gson()
            val templateJson = gson.fromJson(template, JsonObject::class.java)
            val credentialSubjectMap = mutableMapOf<String, Any>()
            templateJson.entrySet().forEach { entry ->
                val key = entry.key
                val value = entry.value.asString
                credentialSubjectMap[key] = value
            }
            if (!clientId.startsWith("did:")) throw IllegalArgumentException("The clientID isn't valid.")

            val authRequest = authRequestRegistry.remove(state) ?: throw IllegalArgumentException("The clientId isn't valid.")


            if (authRequest.clientId == null) throw IllegalArgumentException("The clientId isn't valid.")

            authRequestRegistry[authRequest.clientId] = IssuerCommand.AuthRequest(
                authRequest.codeVerifier,
                authRequest.code,
                authRequest.credentialtype,
                credentialSubjectMap,
                authRequest.expiration,
                redirecUri = authRequest.redirecUri,
                authType = authRequest.authType
            )

            log.debug { "authCode -> [!] Issuer logs: authRequest - ${authRequest.code}" }.toString()
            val locationUri = StringBuilder()
            locationUri.append(authRequest.redirecUri)
            val firstChart = if (authRequest.redirecUri.contains("?")) "&" else "?"
            locationUri.append("${firstChart}code=${authRequest.code}")
            call.respond(locationUri.toString())
        } catch (e: IllegalArgumentException) {
            println("$rojo[!] Error: ${e.message}$reset")
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to e.message))
        } catch (e: Exception) {
            println("$rojo[!] Unexpected Error: ${e.localizedMessage}$reset")
            call.respond(HttpStatusCode.InternalServerError, mapOf("error" to "An unexpected error occurred."))
        }
    }

    fun authInfoResponse(clientId: String, state: String): String {
        val payload = buildJsonObject {
            put("iss", DID_BACKEND)
            put("aud", "https://ePassportreaderapp.com")
            put("sub", clientId)
            put("exp", (System.currentTimeMillis() / 1000) + 60)
            put("response_type", "id_token")
            put("response_mode", "direct_post")
            put("client_id", clientId)
            put("redirect_uri", "https://umu-issuer:${ISSUER_PORT}/code-ePassport")
            put("scope", "openid")
            put("state", state)
            put("nonce", generarValorAleatorio())
        }.toString()

        return  jwtService.sign(KEY_ALIAS, payload)
    }

}
