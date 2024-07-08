package id.walt.cli

import com.github.ajalt.clikt.core.CliktCommand
import io.ktor.server.application.*
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.security.SecureRandom
import java.io.File
import java.nio.charset.Charset
import java.time.Instant
import id.walt.model.credential.status.CredentialStatus
import id.walt.sdjwt.DecoyMode
import id.walt.sdjwt.SDMap
import id.walt.signatory.Ecosystem
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import id.walt.signatory.Signatory
import io.ktor.server.netty.*
import id.walt.services.ecosystems.fabric.VDR
import id.walt.crypto.*
import id.walt.services.did.DidService
import id.walt.services.key.KeyService
import id.walt.services.jwt.JwtService
import io.ktor.server.engine.*
import java.security.KeyStore
import java.io.FileInputStream
import org.slf4j.LoggerFactory
import kotlinx.coroutines.runBlocking
import java.nio.charset.StandardCharsets
import java.net.URLDecoder
import com.google.gson.Gson
import java.security.MessageDigest
import io.ktor.server.request.receiveParameters
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.add
import kotlinx.serialization.json.putJsonArray
import id.walt.services.jwt.WaltIdJwtService
import io.ktor.http.*
import kotlinx.serialization.json.jsonObject
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import id.walt.RESOURCES_PATH
import id.walt.auditor.Auditor
import id.walt.auditor.policies.JsonSchemaPolicy
import id.walt.auditor.policies.SignaturePolicy
import id.walt.credentials.w3c.toPresentableCredential
import id.walt.custodian.Custodian
import id.walt.model.DidMethod
import id.walt.servicematrix.ServiceMatrix
import id.walt.services.keyUmu.KeyServiceUmu
import id.walt.services.storeUmu.KeyStoreServiceUmu
import id.walt.services.vc.JsonLdCredentialService
import inf.um.multisign.MS
import inf.um.multisign.MSauxArg
import inf.um.psmultisign.PSauxArg
import inf.um.psmultisign.PSms
import inf.um.psmultisign.PSprivateKey
import inf.um.psmultisign.PSverfKey
import io.ktor.server.http.content.*
import io.ktor.server.plugins.cors.*
import mu.KotlinLogging
import org.bitcoinj.core.Base58
import java.nio.file.Files
import java.nio.file.Paths
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.util.*
import kotlin.collections.HashSet



/* SSIKIT issuer */
class IssuerCommand :
    CliktCommand(
        name = "issuer",
        help =
        """
                        OIDC4VC issuer
                """
    ) {
    /*

        Estructura que almacena la información asociada al token auth:
            -codeVerifier: Hash del nonce enviado por el usuario (mecanismo de seguridad PKCE)
            -code: valor aleatoria que representar el token del uusario
            -type: Tipo de credenciales que desea obtener.
            -CredentialSubject: Contenido de la credential.
            -expiration: Tiempo de expiración del token (1 min)

    */

    data class AuthRequest(val codeVerifier: String, val code: String, val type: String, val credentialSubject: Map<String, Any>, val expiration: Instant = Instant.now().plusSeconds(60) )


    /*

        Estructura que almacena la información asociada a un Acces token
            -Bearer: JWT
            -nonce.
            -ExpirationTime: Tiempo de expiración (1 min)

    */

    data class TokenInfo(val bearer: String, val nonce: String ,val expirationTime: Instant)

    // Mapa que asocia a cada ClientID un token auth utilizado para la solicitud del access token
    val authRequestRegistry = mutableMapOf<String, AuthRequest>()
    // Mapa que asocia a cada clientID (tras iniciar sesión) su clientSecret
    val clientID = mutableMapOf<String, String>()
    // Mapa que almacena los nombres de los usuarios y las contraseñas (SHA256)
    val clientCredentials = mutableMapOf<String, String>()
    // Mapa encargado de asocida a un client Id el objeto con la información de un access Token
    val tokenRegistry = mutableMapOf<String, TokenInfo>()



    // DID del emisor
    lateinit var DID_BACKEND: String
    // ID de la clave asociada al DID del emisor
    lateinit var KEY_ALIAS: String

    lateinit var assertionMethods: Array<String>


    // Servicios
    val keyService = KeyService.getService()
    val jwtService = WaltIdJwtService()
    private val keyStoreUmu = KeyStoreServiceUmu.getService()
    private val keyServiceUmu = KeyServiceUmu.getService()
    private val credentialService = JsonLdCredentialService.getService()

    // Directorio con los certificados https
    val currentWorkingDir = System.getProperty("user.dir")
    val keyStorePath = "$currentWorkingDir/cert/issuer/issuer.p12"

    // Salida mas legible
    val verde = "\u001B[32m"
    val rojo = "\u001B[31m"
    val reset = "\u001B[0m"

    override fun run() {

        initialization()

        runBlocking {
            var keyStoreFile = File(keyStorePath)

            val keyStorePassword = ""
            val privateKeyPassword = ""
            val keyAlias = "issuer"
            val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
            keyStore.load(FileInputStream(keyStoreFile), keyStorePassword.toCharArray())

            val environment = applicationEngineEnvironment {
                val log = KotlinLogging.logger {}
                connector {
                    port = 4869
                }
                sslConnector(
                    keyStore = keyStore,
                    keyAlias = keyAlias,
                    keyStorePassword = { keyStorePassword.toCharArray() },
                    privateKeyPassword = { privateKeyPassword.toCharArray() }
                ) {
                    port = 8443
                }
                module {

                    // Políticas CORS
                    install(CORS) {
                        allowCredentials = true
                        allowNonSimpleContentTypes = true
                        allowSameOrigin = true
                        anyHost()  // Permite solicitudes CORS desde cualquier origen
                        allowHeader(HttpHeaders.ContentType)
                    }


                    routing {

                        static("/static") {
                            resources("static")
                        }

                        /*
                            Registro de un usuario en el backend, contraseña se guarda en sha-256
                        */

                        post("/registerBackend") {

                            println("\n$verde[+] Issuer: Register a user.$reset\n")

                            val parameters = call.receiveParameters()
                            val user = parameters["user"]
                            val pass = parameters["pass"]

                            log.debug { "registerBackend -> [!] Issuer logs: username - $user password - $pass" }.toString()



                            if (clientCredentials.containsKey(user)) {
                                call.respondText("This username is already registered.")
                            } else {
                                if (user != null && pass != null) {
                                    clientCredentials[user] = pass.sha256()
                                } else {
                                    call.respond(HttpStatusCode.BadRequest, "Username and password fields are required")
                                }
                                call.respondText("The user registered successfully.")
                            }
                        }

                        /*
                            Login de un usuario
                        */

                        post("/loginBackend") {

                            println("\n$verde[+] Issuer: Log in a user.$reset\n")
                            val parameters = call.receiveParameters()
                            val user = parameters["user"]
                            val pass = parameters["pass"]

                            log.debug { "loginBackend -> [!] Issuer logs: username - $user password - $pass" }.toString()

                            if (user != null && pass != null) {
                                if (clientCredentials[user] == pass.sha256()) {

                                    val clientId = UUID.randomUUID().toString()
                                    val clientSecret = UUID.randomUUID().toString()
                                    clientID[clientId] = clientSecret
                                    val jsonResponse = "{\"clientId\":\"$clientId\", \"clientSecret\":\"$clientSecret\"}"
                                    call.respondText(jsonResponse, ContentType.Application.Json)

                                } else {
                                    call.respondText("Invalid username or password.", status = io.ktor.http.HttpStatusCode.Unauthorized)
                                }
                            } else {
                                call.respondText("Invalid username or password.", status = io.ktor.http.HttpStatusCode.Unauthorized)
                            }

                        }

                        /*
                            Endpoint que devuelve los metadatos del emisor, credenciales que puede emitir...
                        */

                        get("/list/.well-known/openid-configuration"){

                            println("\n$verde[+] Issuer: GET OIDC discovery document$reset\n")

                            val jsonFilePath_ProofOfResidence = "src/main/resources/server/credentialJSON/ProofOfResidence.json"
                            val jsonFilePath_VerifiableVaccinationCertificate = "src/main/resources/server/credentialJSON/VerifiableVaccinationCertificate.json"
                            val jsonFilePath_VerifiableDiploma = "src/main/resources/server/credentialJSON/VerifiableDiploma.json"
                            val jsonFilePath_OpenBadgeCredential = "src/main/resources/server/credentialJSON/OpenBadgeCredential.json"
                            val jsonFilePath_Europass = "src/main/resources/server/credentialJSON/Europass.json"
                            val jsonFilePath_VerifiableId = "src/main/resources/server/credentialJSON/VerifiableId.json"
                            val jsonFilePath_ParticipantCredential = "src/main/resources/server/credentialJSON/ParticipantCredential.json"
                            val jsonFilePath_PermanentResidentCard = "src/main/resources/server/credentialJSON/PermanentResidentCard.json"

                            // Lee el contenido del archivo JSON como una cadena
                            var jsonContent_ProofOfResidence = File(jsonFilePath_ProofOfResidence).readText(Charset.defaultCharset())
                            jsonContent_ProofOfResidence = """ "ProofOfResidence" : """+jsonContent_ProofOfResidence
                            var jsonContent_VerifiableVaccinationCertificate = File(jsonFilePath_VerifiableVaccinationCertificate).readText(Charset.defaultCharset())
                            jsonContent_VerifiableVaccinationCertificate = """ "VerifiableVaccinationCertificate" : """+jsonContent_VerifiableVaccinationCertificate
                            var jsonContent_VerifiableDiploma = File(jsonFilePath_VerifiableDiploma).readText(Charset.defaultCharset())
                            jsonContent_VerifiableDiploma = """ "VerifiableDiploma" : """+jsonContent_VerifiableDiploma
                            var jsonContent_OpenBadgeCredential = File(jsonFilePath_OpenBadgeCredential).readText(Charset.defaultCharset())
                            jsonContent_OpenBadgeCredential = """ "OpenBadgeCredential" : """+jsonContent_OpenBadgeCredential
                            var jsonContent_Europass = File(jsonFilePath_Europass).readText(Charset.defaultCharset())
                            jsonContent_Europass = """ "Europass" : """+jsonContent_Europass
                            var jsonContent_VerifiableId = File(jsonFilePath_VerifiableId).readText(Charset.defaultCharset())
                            jsonContent_VerifiableId = """ "VerifiableId" : """+jsonContent_VerifiableId
                            var jsonContent_ParticipantCredential = File(jsonFilePath_ParticipantCredential).readText(Charset.defaultCharset())
                            jsonContent_ParticipantCredential = """ "ParticipantCredential" : """+jsonContent_ParticipantCredential
                            var jsonContent_PermanentResidentCard = File(jsonFilePath_PermanentResidentCard).readText(Charset.defaultCharset())
                            jsonContent_PermanentResidentCard = """ "PermanentResidentCard" : """+jsonContent_PermanentResidentCard

                            var credentials = """{"authorization_endpoint": "https://umu-issuer:8443/auth", "token_endpoint": "https://umu-issuer:8443/token", "pushed_authorization_request_endpoint": "https://umu-issuer:8443/par", "issuer": "https://umu-issuer:8443", "jwks_uri": "https://issuer.walt.id/issuer-api/default/oidc", "grant_types_supported": ["authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code"], "request_uri_parameter_supported": true, "credentials_supported": { """
                            //credentials = credentials + jsonContent_ProofOfResidence + "," + jsonContent_VerifiableVaccinationCertificate + "," + jsonContent_VerifiableDiploma + "," + jsonContent_OpenBadgeCredential + "," + jsonContent_Europass + "," + jsonContent_VerifiableId + "," + jsonContent_ParticipantCredential + "},"
                            //credentials = credentials + jsonContent_PermanentResidentCard + "," + jsonContent_ProofOfResidence + "," + jsonContent_VerifiableId + "," + jsonContent_ParticipantCredential + "},"

                            // Credenciales ofertadas actualmente:

                            credentials = credentials + jsonContent_PermanentResidentCard + "},"

                            credentials = credentials + """ "credential_issuer": {"display" : [{"locale" : null, "name" : "https://umu-issuer:8443/"}]}, "credential_endpoint": "https://umu-issuer:8443/credential", "subject_types_supported": ["public"]} """


                            log.debug { "list/.well-known/openid-configuration -> [!] Issuer logs: Metadata - $credentials" }.toString()

                            call.respond(credentials)
                        }

                        /*

                            Endpoint que comienza con el flujo de emisión del auth token, genera parte del token, pero no lo devuelve hasta
                            completar la comunicación con el siguiente endpoint.

                            Devuelve la url de redirección con la plantilla de atributos que deben rellenarse para la emisión de la credencial
                            con el credentialSubject correcto.

                            (Desde que comienza este paso se dispone de 1 min para que expire el token)

                        */

                        get("/auth") {
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
                                //val types = authDetails["credential_definition"] ?: throw IllegalArgumentException("Missing 'format' in 'authorization_details'.")

                                if (!clientID.containsKey(clientId)) throw IllegalArgumentException("The clientID isn't valid.")
                                if (type != "openid_credential") throw IllegalArgumentException("The type isn't valid.")
                                if (format != "jwt_vc_json") throw IllegalArgumentException("The format isn't valid.")
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
                                authRequestRegistry[clientId] = AuthRequest(codeChallenge.sha256(), code, t, mutableMapOf<String, Any>())

                                // Url con los atributos del credential subject
                                val locationUri = StringBuilder()
                                locationUri.append("https://umu-webWallet:8445/form")
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

                        /*

                            Endpoint que finaliza el proceso de emisión del authToken, registra los atributos del credential subject
                            y devuelve el auth token al usuario para que pueda obtener un access token.

                        */

                        post("/authCode") {
                            println("\n$verde[+] Issuer: POST /authCode request$reset\n")

                            try {

                                val parameters = call.receiveParameters()
                                val type = parameters["type"]
                                val clientId = parameters["clientId"]
                                val template = parameters["template"]

                                if (type.isNullOrEmpty() || clientId.isNullOrEmpty() || template.isNullOrEmpty()) {
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

                                if (!clientID.containsKey(clientId)) {
                                    throw IllegalArgumentException("The clientID isn't valid.")
                                }

                                val authRequest = authRequestRegistry[clientId] ?: throw IllegalArgumentException("The clientId isn't valid.")

                                authRequestRegistry[clientId] = AuthRequest(authRequest.codeVerifier, authRequest.code, type, credentialSubjectMap, authRequest.expiration)

                                log.debug { "authCode -> [!] Issuer logs: authRequest - ${authRequest.code}" }.toString()

                                call.respond(authRequest.code)
                            } catch (e: IllegalArgumentException) {
                                println("$rojo[!] Error: ${e.message}$reset")
                                call.respond(HttpStatusCode.BadRequest, mapOf("error" to e.message))
                            } catch (e: Exception) {
                                println("$rojo[!] Unexpected Error: ${e.localizedMessage}$reset")
                                call.respond(HttpStatusCode.InternalServerError, mapOf("error" to "An unexpected error occurred."))
                            }
                        }


                        /*

                            Endpoint encargada de la emisión del access token, recibe un auth token, cliendId, clientSecret... Si tras realizar toda
                            la verificación todo resulta correcto generará y devolverá el token.

                        */

                        post("/token") {

                            println("\n$verde[+] Issuer: PUSH OIDC access token request$reset\n")

                            val parameters = call.receiveParameters()
                            val grantType = parameters["grant_type"]
                            val code = parameters["code"]
                            val codeVerifier = parameters["code_verifier"]
                            val redirectUri = parameters["redirect_uri"]
                            val authorizationHeader = call.request.headers["Authorization"]

                            var clientId = ""
                            var clientSecret = ""



                            if (grantType.isNullOrEmpty() || code.isNullOrEmpty() || codeVerifier.isNullOrEmpty() || redirectUri.isNullOrEmpty() || authorizationHeader.isNullOrEmpty()) {
                                call.respond(HttpStatusCode.BadRequest, "Missing required parameters")
                                return@post
                            }

                            val decodedCredentials = decodeBasicAuth(authorizationHeader)

                            if (decodedCredentials != null){
                                clientId = decodedCredentials.first
                                clientSecret = decodedCredentials.second
                            }else{
                                call.respond(HttpStatusCode.Unauthorized, "Invalid client credentials")
                                return@post
                            }

                            if (!clientID.containsKey(clientId) || clientID[clientId] != clientSecret) {
                                call.respond(HttpStatusCode.Unauthorized, "Invalid client credentials")
                                return@post
                            }

                            val authRequestInfo = authRequestRegistry[clientId]


                            if (!(authRequestInfo != null &&
                                        authRequestInfo.code == code &&
                                        authRequestInfo.codeVerifier == codeVerifier))
                            {
                                call.respond(HttpStatusCode.BadRequest, "Invalid code or code_verifier")
                                return@post
                            }

                            if(isTokenExpired(authRequestInfo)){
                                call.respond(HttpStatusCode.Unauthorized, "Auth token is expired")
                                return@post
                            }

                            val accessToken = accessTokenResponse(clientId, authRequestInfo.type)

                            log.debug { "token -> [!] Issuer logs: accessToken - ${accessToken}" }.toString()

                            call.respond(accessToken)

                        }

                        /*

                            Endpoint que tras realizar las comprobaciones relacionadas con el accesstoken devuelve la credencial firmada por el issuer

                        */

                        post("/credential"){
                            println("\n$verde[+] Issuer: Get credential from issuer.$reset\n")

                            try{

                                val parameters = call.receiveParameters()
                                val proof = parameters["proof"]?: ""
                                val authorizationHeader = call.request.headers["Authorization"]?: ""
                                val authorization = authorizationHeader.substringAfter("Bearer ", "")




                                val clientId = getValueFromJWT(authorization, "client_id")
                                val subjectDid = getValueFromJWT(proof, "iss")

                                // Comprueba que el access token sea válido (cabecera de autenticación)

                                if (!isAccessTokenValid(authorization)) throw IllegalArgumentException("The authorization header isn't valid.")
                                // Comprueba que el nonce este firmado correctamente

                                if (!isProofValid(proof,clientId)) throw IllegalArgumentException("The proof isn't valid.")  // TODO : la verificación de la firma solo funciona de manera local
                                val authRequestInfo = authRequestRegistry[clientId]
                                if (authRequestInfo == null) throw IllegalArgumentException("The clientId isn't valid.")

                                val templateFilePath = "./src/main/resources/vc-templates/"+authRequestInfo.type+"-template.json"
                                val jsonTemplate = Files.readString(Paths.get(templateFilePath))

                                val gson = Gson()
                                val credential_empty = gson.fromJson(jsonTemplate, JsonObject::class.java)
                                val credentialSubject = credential_empty.getAsJsonObject("credentialSubject")


                                authRequestInfo.credentialSubject.forEach { (key, value) ->
                                    credentialSubject.addProperty(key, value.toString())
                                }


                                val credential = gson.toJson(credential_empty)

                                val n = countCredentialSubjectAttributes(credential)

                                val ldSignatureType: LdSignatureType? = null
                                val issuerVerificationMethod: String? = null
                                val credentialTypes: CredentialStatus.Types? = null
                                val selectiveDisclosurePaths: List<String>? = null

                                // Obtención de la credencial firmada

                                println(n)
                                val credential_signed = CreateCredential(DID_BACKEND ,subjectDid, credential, null, ProofType.LD_PROOF, "assertionMethod", LdSignatureType.PsmsBlsSignature2022, Ecosystem.DEFAULT , null, DecoyMode.NONE, 0, null)


                                log.debug { "Credential -> [!] Issuer logs: credential_signed - ${credential_signed}" }.toString()

                                call.respond(credential_signed)


                            } catch (e: IllegalArgumentException) {
                                println(rojo + "[!] Error: ${e.message}" + reset)
                                call.respond(HttpStatusCode.BadRequest, mapOf("error" to e.message))
                            } catch (e: Exception) {
                                println(rojo + "[!] Unexpected Error: ${e.localizedMessage}" + reset)
                                call.respond(HttpStatusCode.InternalServerError, mapOf("error" to "An unexpected error occurred."))
                            }


                        }

                    }
                }
            }

            embeddedServer(Netty, environment).start(wait = true)

        }

    }

    // Obtiene un determinado valor (v) dentro de un JWT
    fun getValueFromJWT(jwt: String, v: String): String {
        val parts = jwt.split(".")
        val payload = parts[1]
        val decodedPayload = String(Base64.getDecoder().decode(payload))
        val jsonElement = Json.parseToJsonElement(decodedPayload)
        val content = jsonElement.jsonObject[v]?.toString()?.removeSurrounding("\"") ?: throw IllegalArgumentException("Error processing the JWT.")
        return content
    }

    /*

        Verificación de las firmas de un JWT, tanto a nivel local como haciendo resolución de DIDs

    */

    fun verifyJWT(jwt: String): Boolean
    {
        val result = JwtService.getService().verify(jwt).verified
        return result
    }


    // Comprueba que el nonce del accessToken se haya firmado correctamente para completar la emisión de la credencial
    fun isProofValid(proof: String, clientId: String): Boolean {
        val iss =  getValueFromJWT(proof, "iss")
        DidService.importDidAndKeys(iss)
        val tokenInfo = tokenRegistry[clientId] ?: return false
        val c_nonce = getValueFromJWT(proof, "c_nonce")

        if (c_nonce != tokenInfo.nonce) return false

        return verifyJWT(proof)
    }





    // Comprueba la validez de un accesstoken (firma y tiempo de expiración)
    fun isAccessTokenValid(jwt: String): Boolean {

        val parts = jwt.split(".")
        if (parts.size != 3) return false

        val payload = parts[1]
        val decodedPayload = String(Base64.getDecoder().decode(payload))
        val jsonElement = Json.parseToJsonElement(decodedPayload)
        if (!jsonElement.jsonObject.containsKey("iss") ||
            !jsonElement.jsonObject.containsKey("exp") ||
            !jsonElement.jsonObject.containsKey("client_id")) return false

        val clientId = jsonElement.jsonObject["client_id"]?.toString()?.removeSurrounding("\"") ?: return false
        val exp = jsonElement.jsonObject["exp"]?.toString()?.removeSurrounding("\"") ?: return false
        val tokenInfo = tokenRegistry[clientId] ?: return false
        if (tokenInfo.bearer != jwt) return false
        if (!verifyJWT(jwt)) return false
        val currentTime = Instant.now()
        if (tokenInfo.expirationTime.isBefore(currentTime)) return false
        return true
    }

    // Función encargada de devolver un accessToken con el tipo de credencial que se desea emitir.
    fun accessTokenResponse(clientId: String, type: String):String{
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
        tokenRegistry[clientId] = TokenInfo(bearer,nonce,expirationTime)
        return responseJson.toString()
    }


    // Crea una credencial firmada con el DID del issuer
    fun CreateCredential(issuerDid: String, subjectDid: String, template: String ,issuerVerificationMethod: String?, proofType: ProofType, proofPurpose: String, ldSignatureType: LdSignatureType?, ecosystem: Ecosystem , statusType: CredentialStatus.Types?, decoyMode: DecoyMode, numDecoys: Int, selectiveDisclosurePaths: List<String>?): String {

        val signatory = Signatory.getService()
        val selectiveDisclosure = selectiveDisclosurePaths?.let { SDMap.generateSDMap(it, decoyMode, numDecoys) }
        val vcStr: String = runCatching {
            signatory.issue_umu(
                template, ProofConfig(
                    issuerDid = issuerDid,
                    subjectDid = subjectDid,
                    issuerVerificationMethod = issuerVerificationMethod,
                    proofType = proofType,
                    proofPurpose = proofPurpose,
                    ldSignatureType = ldSignatureType,
                    ecosystem = ecosystem,
                    statusType = statusType,
                    creator = issuerDid,
                    selectiveDisclosure = selectiveDisclosure
                )

            )
        }.getOrElse { err ->
            when (err) {
                is IllegalArgumentException -> echo("Illegal argument: ${err.message}")
                else -> echo("Error: ${err.message}")
            }
            return "Error creating the VC"
        }

        return vcStr
    }


    /*

        Realiza un sha256:
            -Almacenamiento de la contraseña de los usuarios
            -Verificación en el mecanismo PKCE del código de verificación

    */

    fun String.sha256(): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(this.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }


    // Genreación de un valor aleatorio
    fun generarValorAleatorio(): String {
        val secureRandom = SecureRandom()
        val bytes = ByteArray(32)
        secureRandom.nextBytes(bytes)

        val base64String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        val randomvalue = base64String.substring(0, 16) + "-" + base64String.substring(16)

        return randomvalue
    }

    // Decodificación de la cabecera de autenticacion en el endpoint de generación del access token
    fun decodeBasicAuth(authHeader: String): Pair<String, String>? {
        if (!authHeader.startsWith("Basic ")) return null
        val base64Credentials = authHeader.removePrefix("Basic ")
        val credentials = String(Base64.getDecoder().decode(base64Credentials), Charsets.UTF_8)
        val clientIdSecret = credentials.split(":", limit = 2)
        if (clientIdSecret.size != 2) return null

        return Pair(clientIdSecret[0], clientIdSecret[1])
    }

    // Comprueba que el auth token no se encuentre expirado
    fun isTokenExpired(authRequest: AuthRequest): Boolean {

        val currentTime = Instant.now()
        if (authRequest.expiration.isBefore(currentTime)) return true
        return false
    }

    fun countCredentialSubjectAttributes(credentialJson: String): Int {
        val jsonElement = JsonParser.parseString(credentialJson)
        val jsonObject = jsonElement.asJsonObject
        val credentialSubject = jsonObject.getAsJsonObject("credentialSubject")
        return credentialSubject.keySet().size
    }


    fun initialization(){



        val attrNames_2: Set<String> = HashSet<String>(
            Arrays.asList(
                "http://schema.org/familyName",
                "http://schema.org/birthDate",
                "http://schema.org/gender",
                "http://schema.org/givenName",
                "https://w3id.org/citizenship#birthCountry"
            )
        )

        val kid_fabric = keyServiceUmu.generate(attrNames_2)
        keyStoreUmu.addAlias(kid_fabric, kid_fabric.id)

        val kid_key = keyService.generate(KeyAlgorithm.EdDSA_Ed25519)
        keyService.addAlias(kid_key,kid_key.id)

        DID_BACKEND = DidService.createUmu(kid_fabric.id,DidMethod.fabric,null,kid_key.id)
        //DID_BACKEND = DidService.createUmuMultiKey(kid_key.id,15)
        println("issuer did: "+DID_BACKEND)

        val did2 = DidService.loadDid(DID_BACKEND).toString()

        /*
        val jsonElement = JsonParser.parseString(did2)
        val jsonObject = jsonElement.asJsonObject
        val assertionMethodArray = jsonObject.getAsJsonArray("assertionMethod")
        assertionMethods = assertionMethodArray.map { it.asString }.toTypedArray()
        assertionMethods.forEach { println(it) }
*/


        KEY_ALIAS = kid_key.id
        clientCredentials["p"] = "p".sha256()






    }





}

