package id.walt.cli

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.routing.*
import io.ktor.server.response.*
import io.ktor.http.*
import io.ktor.server.http.content.*
import kotlinx.coroutines.runBlocking
import com.github.ajalt.clikt.core.CliktCommand
import org.slf4j.LoggerFactory
import java.io.File
import id.walt.services.jwt.WaltIdJwtService
import id.walt.services.vc.JsonLdCredentialService
import io.ktor.server.request.receiveParameters
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.serialization.kotlinx.json.*
import id.walt.services.oidc.OIDC4CIService
import java.security.SecureRandom
import com.google.gson.Gson
import id.walt.model.oidc.*
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import io.ktor.client.request.forms.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.jsonObject
import io.ktor.server.engine.embeddedServer
import com.google.gson.JsonParser
import com.nimbusds.oauth2.sdk.AuthorizationRequest
import java.io.FileInputStream
import java.security.KeyStore
import io.ktor.server.request.receiveText
import id.walt.custodian.Custodian
import id.walt.credentials.w3c.VerifiableCredential
import id.walt.credentials.w3c.toVerifiableCredential
import java.net.URI
import id.walt.services.oidc.OIDC4VPService
import id.walt.common.KlaxonWithConverters
import id.walt.credentials.w3c.toPresentableCredential
import id.walt.credentials.w3c.toVerifiablePresentation
import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.KeyIdUmu
import id.walt.crypto.KeyUmu
import id.walt.model.DidMethod
import id.walt.model.dif.PresentationDefinition
import id.walt.services.context.ContextManager
import id.walt.services.did.DidService
import id.walt.services.oidc.CompatibilityMode
import id.walt.services.ecosystems.fabric.VDR
import id.walt.services.key.KeyService
import id.walt.services.keyUmu.KeyServiceUmu
import id.walt.services.keystore.KeyStoreService
import id.walt.services.storeUmu.KeyStoreServiceUmu
import inf.um.multisign.MS
import inf.um.multisign.MSauxArg
import inf.um.psmultisign.PSauxArg
import inf.um.psmultisign.PSms
import inf.um.psmultisign.PSprivateKey
import inf.um.psmultisign.PSverfKey
import mu.KotlinLogging
import java.util.*
import kotlin.collections.HashSet


/* SSIKIT issuer */
class WebWalletCommand:
    CliktCommand(
        name = "web-wallet",
        help = "Start web wallet"
    ) {

    // Servicios
    private val jsonLdCredentialService = JsonLdCredentialService.getService()
    private val keyStoreUmu = KeyStoreServiceUmu.getService()
    private val keyServiceUmu = KeyServiceUmu.getService()
    private val credentialService = JsonLdCredentialService.getService()


    // ENDPOINTS ISSUER
    val ENDPOINT_LIST_CREDENTIALS = "https://umu-issuer:8443/list"
    val ENDPOINT_AUTH = "https://umu-issuer:8443/auth"
    val ENDPOINT_CODE = "https://umu-issuer:8443/authCode"
    val ENDPOINT_TOKEN = "https://umu-issuer:8443/token"
    val ENDPOINT_CREDENTIAL = "https://umu-issuer:8443/credential"
    val ENDPOINT_LOGIN = "https://umu-issuer:8443/login"
    val ENDPOINT_REGISTER = "https://umu-issuer:8443/register"


    // ENDPOINTS VERIFIER
    val ENDPOINT_OBTAIN_VP = "https://umu-verifier:8444/obtainVP"
    val ENDPOINT_VERIFY_VP = "https://umu-verifier:8444/verifyVP"

    // Salida mas legible
    val verde = "\u001B[32m"
    val rojo = "\u001B[31m"
    val reset = "\u001B[0m"

    // DID
    val jwtService = WaltIdJwtService()
    val currentWorkingDir = System.getProperty("user.dir")
    val keyStorePath = "$currentWorkingDir/cert/webWallet/webWallet.p12"

    // GLOBAL

    var challenge = ""
    var last_vp_token: String? = null
    var last_authorization_request: AuthorizationRequest? = null
    val keyService = KeyService.getService()

    // DID del wallet
    lateinit var DID_BACKEND: String
    // ID de la clave asociada al DID del WALLET
    lateinit var KEY_ALIAS: String



    override fun run() {

        initialization()

        runBlocking {
            var keyStoreFile = File(keyStorePath)
            val keyStorePassword = ""
            val privateKeyPassword = ""
            val keyAlias = "webWallet"
            val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
            keyStore.load(FileInputStream(keyStoreFile), keyStorePassword.toCharArray())

            val environment = applicationEngineEnvironment {
                val log = KotlinLogging.logger {}
                connector {
                    port = 9421
                }
                sslConnector(
                    keyStore = keyStore,
                    keyAlias = keyAlias,
                    keyStorePassword = { keyStorePassword.toCharArray() },
                    privateKeyPassword = { privateKeyPassword.toCharArray() }
                ) {
                    port = 8445
                }
                module {
                    routing {

                        /*
                        
                        Endpoints para obtener el frontend del wallet

                        */

                        static("/static") {
                            resources("static")
                        }

                        get("/") {
                            val indexHtml = javaClass.classLoader.getResource("static/wallet/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }

                        get("/form") {
                            val indexHtml = javaClass.classLoader.getResource("static/form/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }

                        get("/login") {
                            val indexHtml = javaClass.classLoader.getResource("static/login/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }

                        get("/register") {
                            val indexHtml = javaClass.classLoader.getResource("static/register/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }

                        get("/credentials") {
                            val indexHtml = javaClass.classLoader.getResource("static/credentials/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }

                        get("/selectCredential") {
                            val indexHtml = javaClass.classLoader.getResource("static/selectCredential/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }

                        get("/demo") {
                            val vpToken = call.request.queryParameters["vpToken"]
                            if (vpToken==null && last_vp_token==null) throw IllegalArgumentException("Invalid vpToken.")
                            if (vpToken!=null) last_vp_token = vpToken
                            val indexHtml = javaClass.classLoader.getResource("static/demoWallet/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }

                        /*
                        
                        Endpoints del backend

                        */


                        // Obtiene y parsea los metadatos del issuer

                        post("/metadata"){

                            val parameters = call.receiveParameters()
                            val issuer = parameters["issuer"]

                            if ( issuer == null)
                                throw IllegalArgumentException("Invalid issuer")

                            val client = HttpClient() {
                                install(ContentNegotiation) { json() }
                                expectSuccess = false
                            }

                            val types = get_OIDC_discovery_document(client,issuer)

                            log.debug{"metadata -> [!] WebWallet logs: types - ${types.toString()}"}

                            call.respond(types.toString())
                            client.close()
                        }



                        /*                         

                            Comienza el proceso apra obtener el auth Token (este endpoint devuelve la url donde se
                            especificarán los parámetros del credential Subject)

                        */

                        post("/credentialParameters"){

                            val parameters = call.receiveParameters()
                            val clientId = parameters["clientId"]
                            val template = parameters["template"]

                            if ( clientId == null || template == null)
                                throw IllegalArgumentException("Invalid parameters")

                            val client = HttpClient() {
                                install(ContentNegotiation) { json() }
                                expectSuccess = false
                            }
                            challenge = generarStateAleatorio()
                            val uri = push_credential_parameters(client, challenge, clientId, template)

                            log.debug{"credentialParameters -> [!] WebWallet logs: uri - ${uri}"}

                            call.respond(uri)
                            client.close()
                        }


                        /*
                        
                            Completa la creación de la credencial:
                                -1: Realiza el segundo paso para obtener el auth token (especificando los valores del credential Subject)
                                -2: Intercambiar el auth_token por el access_token.
                                -3: Solicita la creación de la credencial.
                                -4: Devuelve la credencial generada

                        */

                        post("/createCredential"){

                            val receivedContent = call.receiveText()
                            val json = Json.parseToJsonElement(receivedContent).jsonObject
                            val clientID = json["clientId"]?.toString()?.removeSurrounding("\"") ?: throw IllegalArgumentException("clientID not found")
                            val credentialType = json["type"]?.toString()?.removeSurrounding("\"") ?: throw IllegalArgumentException("type not found")
                            val templateJson = json["template"]?.toString()?.removeSurrounding("\"") ?: throw IllegalArgumentException("template not found")
                            val clientSecret = json["clientSecret"]?.toString()?.removeSurrounding("\"") ?: throw IllegalArgumentException("clientSecret not found")

                            val client = HttpClient() {
                                install(ContentNegotiation) { json() }
                                expectSuccess = false
                            }

                            if ( clientID == null || clientSecret == null || credentialType == null || clientSecret == null)
                                throw IllegalArgumentException("Invalid parameters")

                            // AUTH
                            val auth_code = push_OIDC_auth_request(client, clientID, credentialType, templateJson)

                            // ACCESS TOKEN
                            val token = get_Access_Token(client, auth_code, challenge, clientID, clientSecret,"example.com")

                            // CREDENTIAL
                            val credential = getCredential(client, token)

                            log.debug{"createCredential -> [!] WebWallet logs: credential - ${credential}"}

                            call.respond(credential)
                            client.close()
                        }


                        /*

                            Devuelve el listado de credenciales almacenadas en el wallet

                        */

                        get("/listCredentials"){
                            call.respond(listCredential())
                        }

                        /*
                        
                            Endpoint para almacenar una credencial que hemos recibido del issuer

                        */

                        post("/storeCredential"){
                            val parameters = call.receiveParameters()
                            val credential = parameters["credential"]
                            val name = parameters["nameCred"]
                            if (credential == null || name == null) throw IllegalArgumentException("Invalid parameters")
                            log.debug{"storeCredential -> [!] WebWallet logs: name - ${name}"}
                            saveCredential(credential,name)
                        }

                        /*
                        
                            Elimina una credencial que se encuentra almacenada en el wallet

                        */

                        post("/deleteCredential"){
                            val parameters = call.receiveParameters()

                            val name = parameters["nameCred"]
                            if (name == null) throw IllegalArgumentException("Invalid parameters")

                            deleteFile(name)
                            log.debug{"deleteCredential -> [!] WebWallet logs: name - ${name}"}
                        }

                        /*
                        
                            Parsea los datos del último vp token (política solicitada) y lo devuelve para que se muestre por 
                            pantalla (demo).

                        */

                        get("/vpTokenDetails"){
                            if (last_vp_token == null) throw IllegalArgumentException("Invalid parameters")
                            log.debug{"vpTokenDetails -> [!] WebWallet logs: vpTokenDetails - ${vpTokenDetails()}"}
                            call.respond(vpTokenDetails())
                        }

                        /*
                            Comprueba del listado de credenciales que hay en local cuales cumples la política 
                            solicitada.

                            Devuelve el listado que cumplen la política
                        */

                        get("/validCredentials"){
                            val client = HttpClient() {
                                install(ContentNegotiation) { json() }
                                expectSuccess = false
                            }


                            val list = obtainValidCredentialsDemo(client)
                            log.debug{"validCredentials -> [!] WebWallet logs: list - ${list}"}
                            call.respond(list)

                            client.close()
                        }

                        /*
                        
                            Selecciona una credencial para generar la presentación que satisface la política solicitada. Además se comunica
                            con el verifier para generar el JWT que autorice al usuario.

                        */

                        post("/selectCredential") {
                            val credential = call.receiveText()
                            if (credential.isEmpty()) throw IllegalArgumentException("Invalid parameters")

                            val client = HttpClient() {
                                install(ContentNegotiation) { json() }
                                expectSuccess = false
                            }
                            // Función para generar una derivación de una credencial con zkp
                            val result = DeriveCredential(client, credential)
                            // Función si queremos generar una presentación sin zkp
                            // val result = VerfiablePresentation(client, credential)
                            log.debug{"selectCredential -> [!] WebWallet logs: result - ${result}"}
                            call.respond(result)

                            client.close()
                        }
                    }

                }
            }

            embeddedServer(Netty, environment).start(wait = true)
        }
    }


    // Comunicación con el endpoint del issuer para solicitar la emisión de la credencial.
    suspend fun getCredential(client: HttpClient, tokenResponse: String): String {
        println("\n$verde[+] Wallet: GET credential.$reset\n")

        val jsonElement = JsonParser.parseString(tokenResponse)
        if (!jsonElement.isJsonObject) throw IllegalArgumentException("Invalid JSON response")

        val jsonObject = jsonElement.asJsonObject
        val accessToken = jsonObject["access_token"]?.asString ?: throw IllegalArgumentException("Access token not found")
        val cNonce = jsonObject["c_nonce"]?.asString ?: throw IllegalArgumentException("c_nonce not found")


        val signedJWT = generateDidProof(cNonce)

        val response = client.post(ENDPOINT_CREDENTIAL) {
            header(HttpHeaders.Authorization, "Bearer $accessToken")

            setBody(FormDataContent(Parameters.build {
                append("proof", signedJWT)
            }))
        }
        val credential = response.bodyAsText()
        return credential
    }



    // Partiendo de un auth token obtiene el access token que permite solicitar la emisión de una credencial
    suspend fun get_Access_Token(client: HttpClient, authCode: String, code: String, clientId: String, clientSecret: String, redirectUri: String): String {
        println("\n$verde[+] Wallet: GET access Token.$reset\n")


        val authHeaderValue = Base64.getEncoder().encodeToString("$clientId:$clientSecret".toByteArray(Charsets.UTF_8))
        val response = client.post(ENDPOINT_TOKEN) {
            header(HttpHeaders.Authorization, "Basic $authHeaderValue")
            header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)

            setBody(FormDataContent(Parameters.build {
                append("grant_type", "authorization_code")
                append("code", authCode)
                append("code_verifier", code.sha256())
                append("redirect_uri", redirectUri)
            }))
        }


        val token: String = response.bodyAsText()
        return token
    }

    // Registro de un usuario en el backend del issuer

    suspend fun registerUser(client: HttpClient, username: String, password: String): HttpResponse {

        val response = client.post(ENDPOINT_REGISTER) {
            header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                append("user", username)
                append("pass", password)
            }))
        }

        return response
    }

    // login de un usuario en el backend del issuer (obteniendo cliendID y clientSecret como cookies en el navegador)

    suspend fun loginUser(client: HttpClient, username: String, password: String): Pair<String, String> {
        val response = client.post(ENDPOINT_LOGIN) {
            header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                append("user", username)
                append("pass", password)
            }))
        }


        if (response.status == HttpStatusCode.OK) {
            val responseBody = response.bodyAsText()
            val jsonElement = JsonParser.parseString(responseBody)
            if (jsonElement.isJsonObject) {
                val jsonObject = jsonElement.asJsonObject
                val clientId = jsonObject["clientId"]?.asString
                val clientSecret = jsonObject["clientSecret"]?.asString
                if (clientId != null && clientSecret != null) {
                    return Pair(clientId, clientSecret)
                }
            }
            throw IllegalArgumentException("clientId or clientSecret not found")
        }
        return Pair("","")
    }


    // Función que finaliza el procesos de obtención del auth token tras comunicarse con el issuer

    suspend fun push_OIDC_auth_request(client: HttpClient, clientId: String, type: String, template: String): String {
        println("\n$verde[+] Wallet: PUSH OIDC authcode request$reset\n")

        val response = client.post(ENDPOINT_CODE) {
            header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                append("clientId", clientId)
                append("type", type)
                append("template", template)
            }))
        }

        if (response.status == HttpStatusCode.OK) {
            val code: String = response.bodyAsText()
            return code
        } else {
            println("$rojo[!] Error: ${response.status.description}$reset")
            throw Exception("Error during OIDC auth request: ${response.status.description}")
        }
    }

    /*     
        Comienzo del proeceso de emisión de un auth token, devuelve el uri de redirección con la plantilla
        donde se especifican los valores del credential subject necesarios. 
    */

    suspend fun push_credential_parameters(client: HttpClient, challenge: String, clientId: String, type: String): String {

        println("\n$verde[+] Wallet: PUSH credential parameters request$reset\n")

        val responseType = "code"
        val codeChallengeMethod = "S256"
        val redirectUri = URLEncoder.encode("https://client.example.org/cb", StandardCharsets.UTF_8.name())

        val authorizationDetails = mapOf(
            "type" to "openid_credential",
            "format" to "jwt_vc_json",
            "credential_definition" to mapOf(
                "type" to listOf("VerifiableCredential", type)
            )
        )

        val authorizationDetailsJson = Gson().toJson(authorizationDetails)
        val authorizationDetailsEncoded = URLEncoder.encode(authorizationDetailsJson, StandardCharsets.UTF_8.name())

        val url = URLBuilder(ENDPOINT_AUTH).apply {
            parameters.append("response_type", responseType)
            parameters.append("client_id", clientId)
            parameters.append("code_challenge", challenge)
            parameters.append("code_challenge_method", codeChallengeMethod)
            parameters.append("authorization_details", authorizationDetailsEncoded)
            parameters.append("redirect_uri", redirectUri)
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


    // Función encargada de obtener y parsear los metadatos del issuer

    suspend fun get_OIDC_discovery_document(client: HttpClient, endpoint: String): MutableList<String>{

        val issuer = OIDC4CIService.getWithProviderMetadata(OIDCProvider(endpoint, endpoint))
        val supportedCredentialsList = mutableListOf<String>()
        OIDC4CIService.getSupportedCredentials(issuer).forEach { supported_cred ->
            supportedCredentialsList.add(supported_cred.key)
        }
        return  supportedCredentialsList;
    }


    // Obtención del listado de credenciales que satisfacen una política dada.

    suspend fun obtainValidCredentialsDemo(client: HttpClient): String {

        println("\n$verde[+] Wallet: Obtain valid credentials $reset\n")

        val req = OIDC4VPService.parseOIDC4VPRequestUri(URI.create(last_vp_token))
        if (req == null){
            println("Error parsing SIOP request")
            return """{"error": "Error parsing SIOP request"}"""
        }
        val presentationDefinition = OIDC4VPService.getPresentationDefinition(req)
        last_authorization_request = req
        val (credentialTypes,paths ,credentialSubjectAttributes) = extractPresentationDefinitionInfo(KlaxonWithConverters().toJsonString(presentationDefinition))
        val list = verifyCredentials(credentialTypes,paths ,credentialSubjectAttributes)
        var creds = "{"
        list.forEachIndexed { index, vc ->
            creds += "\"${index + 1}\": [ $vc ]"
            if (index < list.size - 1) {
                creds += ","
            }
        }
        creds += "}"

        return creds
    }

    // Recibe la credenciales seleccionada, generada la VP y se comunica con el issuer para recibir el JWT necesario.

    suspend fun VerfiablePresentation(client: HttpClient, credential: String): String {

        println("\n$verde[+] Wallet: Creating a VP $reset\n")
        val presentation = createVerifiablePresentation(credential).toVerifiablePresentation()
        if (last_authorization_request == null) return "ERROR"
        val resp = OIDC4VPService.getSIOPResponseFor(last_authorization_request!!, DID_BACKEND, listOf(presentation),KEY_ALIAS)
        val url2 = "http://oidc4vp-proxy:8080"+"/ngsi-ld/v1/entities/urn:a.*"
        val result = OIDC4VPService.postSIOPResponse_UMU(last_authorization_request!!, resp, CompatibilityMode.OIDC, "GET", url2, "requester de ejemplo", URI.create(ENDPOINT_VERIFY_VP))
        return result
    }

    suspend fun DeriveCredential(client: HttpClient, credential: String): String {


        val presentationDefinition = OIDC4VPService.getPresentationDefinition(last_authorization_request!!)
        val (credentialTypes,paths ,credentialSubjectAttributes) = extractPresentationDefinitionInfo(KlaxonWithConverters().toJsonString(presentationDefinition))

        val frame = generarFrame(credentialTypes,paths)

        //val frame = "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://w3id.org/citizenship/v1\",\"https://ssiproject.inf.um.es/security/psms/v1\"],\"@type\":[\"VerifiableCredential\",\"PermanentResidentCard\"],\"credentialSubject\":{\"@type\":\"PermanentResident\",\"@explicit\":true,\"givenName\":{},\"gender\":{}}}"
        
        val nonce = generarStateAleatorio()

        val issuer = getIssuer(credential)

        if (issuer != null){
            val deriveVC = credentialService.deriveVC(credential, issuer = issuer, challenge = nonce, frame = frame, domain = null, expirationDate = null);

            val presentation = createVerifiablePresentation(deriveVC).toVerifiablePresentation()
            if (last_authorization_request == null) return "ERROR"
            val resp = OIDC4VPService.getSIOPResponseFor(last_authorization_request!!, DID_BACKEND, listOf(presentation),KEY_ALIAS)
            val url2 = "http://oidc4vp-proxy:8080"+"/ngsi-ld/v1/entities/urn:a.*"
            val result = OIDC4VPService.postSIOPResponse_UMU(last_authorization_request!!, resp, CompatibilityMode.OIDC, "GET", url2, "requester de ejemplo",URI.create(ENDPOINT_VERIFY_VP))

            return result
        }
        else
        {
            throw Exception("It has not been possible to obtain the credential issuer")
        }


    }

    // Generación de la verifiable presentation

    fun createVerifiablePresentation(credential: String): String {
        try {


            val presentableCredentials = listOf(credential.toPresentableCredential())

            val presentation = jsonLdCredentialService.present(
                vcs = presentableCredentials,
                holderDid = DID_BACKEND,
                domain = null,
                challenge = null,
                expirationDate = null
            )

            return presentation
        } catch (e: Exception) {
            e.printStackTrace()
            return "Error creating the verifiable presentation: ${e.message}"
        }


    }

    // Elimina una credencial almanecada en el wallet

    fun deleteFile(name: String): Boolean {
        val filePath = "./data/credential-store/custodian/"+name+".cred"
        val file = File(filePath)
        if (file.exists()) {
            file.delete()
            return true
        } else {
            return false
        }
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

    // Almacena una credencial en el wallet

    fun saveCredential(credential:String, name:String) {
        println("\n$verde[+] Wallet: Save credential $reset\n")
        val cred = credential.toVerifiableCredential()
        Custodian.getService().storeCredential(name, cred)
    }


    // Lista el conjunto de credenciales almacenadas

    fun listCredential(): String{

        println("\n$verde[+] Wallet: List credential $reset\n")

        var creds = "{"
        val verifiableCreds = Custodian.getService().listCredentials()
        verifiableCreds.forEachIndexed { index, vc ->
            creds += "\"${index + 1}\": [ $vc ]"
            if (index < verifiableCreds.size - 1) {
                creds += ","
            }
        }
        creds += "}"

        return creds
    }


    // Genera un valor aleatorio (utilizando para la generación del challenge en el obtención del auth token)
    fun generarStateAleatorio(): String {
        val secureRandom = SecureRandom()
        val bytes = ByteArray(32)
        secureRandom.nextBytes(bytes)

        val base64String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        val random = base64String.substring(0, 16) + "-" + base64String.substring(16)

        return random
    }

    // Función para realizar el hash 256

    fun String.sha256(): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(this.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    // Genera de forma dinámica un frame para realizar la derivación

    fun generarFrame(credentialType: MutableList<String>, atributos: MutableList<String>): String {
            val contextos = listOf(
                "\"https://www.w3.org/2018/credentials/v1\"",
                "\"https://w3id.org/citizenship/v1\"",
                "\"https://ssiproject.inf.um.es/security/psms/v1\""
            )

            val tipos = mutableListOf("\"VerifiableCredential\"")
            tipos.addAll(credentialType.map { "\"$it\"" })

            val atributosCredencial = atributos.map {
                it.replace("$.credentialSubject.", "") to "{}"
            }.toMap()

            val tipoCredencial = if (credentialType.contains("PermanentResidentCard")) "\"PermanentResident\"" else "\"\""

            val json = """
                {
                  "@context": [${contextos.joinToString(", ")}],
                  "@type": [${tipos.joinToString(", ")}],
                  "credentialSubject": {
                    "@type": $tipoCredencial,
                    "@explicit": true,
                    ${atributosCredencial.map { "\"${it.key}\": ${it.value}" }.joinToString(",\n        ")}
                  }
                }
                """.trimIndent()

            return json
    }





        // Obtención de la política indicada por el verifier

    fun extractPresentationDefinitionInfo(json: String):Triple<MutableList<String>, MutableList<String>, MutableList<String>>{
        val gson = Gson()
        val presentationDefinition = gson.fromJson(json, PresentationDefinition::class.java)
        val credentialTypes = mutableListOf<String>()
        val credentialSubjectAttributes = mutableListOf<String>()
        val paths = mutableListOf<String>()
        presentationDefinition.input_descriptors.forEach { descriptor ->
            descriptor.constraints?.fields?.forEach { field ->
                field.filter?.let { filter ->
                    (filter["const"] as? String)?.let { constValue ->
                        credentialSubjectAttributes.add(constValue)
                    }
                    (filter["contains"] as? Map<*, *>)?.get("const")?.let { containsConstValue ->
                        if (containsConstValue is String) {
                            credentialTypes.add(containsConstValue)
                        }
                    }
                }
                val pathString = field.path.joinToString(separator = ", ")
                if (pathString != "$.type") paths.add(pathString)
            }
        }


        return Triple(credentialTypes,paths ,credentialSubjectAttributes)
    }


    /*
        Al igual que la anterior función parsea el mensaje del verifier para obtener la política solicitada y
        devolver una seria de listas en formato String con la información relevante (tipos de credenciales, atributos
        y valores de esos atributos...)
    */

    fun vpTokenDetails(): String {

        val req = OIDC4VPService.parseOIDC4VPRequestUri(URI.create(last_vp_token))
        if (req == null){
            println("Error parsing SIOP request")
            return """{"error": "Error parsing SIOP request"}"""
        }
        val definition = OIDC4VPService.getPresentationDefinition(req)
        val gson = Gson()
        val presentationDefinition = gson.fromJson(KlaxonWithConverters().toJsonString(definition), PresentationDefinition::class.java)
        val credentialTypes = mutableListOf<String>()
        val credentialSubjectAttributes = mutableListOf<String>()
        val paths = mutableListOf<String>()
        presentationDefinition.input_descriptors.forEach { descriptor ->
            descriptor.constraints?.fields?.forEach { field ->
                field.filter?.let { filter ->
                    (filter["const"] as? String)?.let { constValue ->
                        credentialSubjectAttributes.add(constValue)
                    }
                    (filter["contains"] as? Map<*, *>)?.get("const")?.let { containsConstValue ->
                        if (containsConstValue is String) {
                            credentialTypes.add(containsConstValue)
                        }
                    }
                }
                val pathString = field.path.joinToString(separator = ", ")
                if (pathString != "$.type") paths.add(pathString)
            }
        }

        return credentialTypes.toString()+paths.toString()+credentialSubjectAttributes.toString()

    }


    fun resolveDid(key: String): String?{
        return VDR.getValue(key)
    }

    // Función que recorrer el listado de credenciales almanceandas para ver el listado de ellas que cumplen una determinada política

    fun verifyCredentials(
        credentialTypes: List<String>,
        credentialSubjectAttributesFullPath: List<String>,
        credentialSubjectValues: List<String>
    ): List<VerifiableCredential> {
        val matchingCredentials = mutableListOf<VerifiableCredential>()
        val verifiableCreds = Custodian.getService().listCredentials()
        val credentialSubjectAttributes = credentialSubjectAttributesFullPath.map { it.split(".").last() }

        verifiableCreds.forEach { vc ->
            if (vc.type.any { credentialTypes.contains(it) }) {
                val credentialSubject = vc.credentialSubject ?: return@forEach
                val matchesAllAttributes = credentialSubjectAttributes.indices.all { index ->
                    val attributeKey = credentialSubjectAttributes[index]
                    val expectedValue = credentialSubjectValues[index]
                    val actualValue = credentialSubject.properties[attributeKey]?.toString()

                    expectedValue == actualValue
                }
                if (matchesAllAttributes) {
                    matchingCredentials.add(vc)
                }
            }
        }

        return matchingCredentials
    }

    private fun getIssuer(credential: String): String? {
        val jsonString = credential.trimIndent()
        val jsonElement = Json.parseToJsonElement(jsonString)
        val issuer = jsonElement.jsonObject["issuer"]?.toString()?.replace("\"", "")

        return issuer
    }

    fun initialization(){


        val attrNames_2: Set<String> = java.util.HashSet<String>(
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

        val kid_key = DidService.keyService.generate(KeyAlgorithm.EdDSA_Ed25519)
        DidService.keyService.addAlias(kid_key,kid_key.id)

        //DID_BACKEND = DidService.createUmuMultiKey(kid_key.id, 15)

        DID_BACKEND = DidService.createUmu(kid_fabric.id,DidMethod.fabric,null,kid_key.id)

        KEY_ALIAS = kid_key.id
        println("webwallet did: "+DID_BACKEND)



    }
}

