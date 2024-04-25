package id.walt.cli

import com.beust.klaxon.Klaxon
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
import java.util.Base64
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
import id.walt.model.dif.PresentationDefinition
import id.walt.services.oidc.CompatibilityMode
import java.net.URLDecoder



/* SSIKIT issuer */
class WebWalletCommand:
        CliktCommand(
                name = "web-wallet",
                help = "Start web wallet"
        ) {




    private val jsonLdCredentialService = JsonLdCredentialService.getService()

    // ENDPOINTS ISSUER
    val ENDPOINT_LIST_CREDENTIALS = "https://localhost:8443/list"
    val ENDPOINT_AUTH = "https://localhost:8443/auth"
    val ENDPOINT_CODE = "https://localhost:8443/authCode"
    val ENDPOINT_TOKEN = "https://localhost:8443/token"
    val ENDPOINT_CREDENTIAL = "https://localhost:8443/credential"
    val ENDPOINT_LOGIN = "https://localhost:8443/login"
    val ENDPOINT_REGISTER = "https://localhost:8443/register"
    

    // ENDPOINTS VERIFIER
    val ENDPOINT_OBTAIN_VP = "https://localhost:8444/obtainVP"
    val ENDPOINT_VERIFY_VP = "https://localhost:8444/verifyVP"

    // Salida mas legible
    val verde = "\u001B[32m"
    val rojo = "\u001B[31m"
    val reset = "\u001B[0m"

    // DID

    val jwtService = WaltIdJwtService()
    val WALLET_DID = "did:key:z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc"
    val KEY_ALIAS = "131ae91a20504a8b8b8a7dbce1660a61"
    val DOC = """ 
    {"assertionMethod":["did:key:z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc#z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc"],"authentication":["did:key:z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc#z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc"],"capabilityDelegation":["did:key:z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc#z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc"],"capabilityInvocation":["did:key:z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc#z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc"],"@context":"https://www.w3.org/ns/did/v1","id":"did:key:z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc","keyAgreement":["did:key:z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc#z6LSpECQnDNxJJW2taojbwXixVp6DpET6rjnZCQfVHyuRuUH"],"verificationMethod":[{"controller":"did:key:z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc","id":"did:key:z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc#z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc","publicKeyBase58":"CvRH1Cvpyz5ogbw3Ajm3Jk4vEroDd4Rvap72iw8HvyRE","type":"Ed25519VerificationKey2019"},{"controller":"did:key:z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc","id":"did:key:z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc#z6LSpECQnDNxJJW2taojbwXixVp6DpET6rjnZCQfVHyuRuUH","publicKeyBase58":"DZ2FFua6CqnHoCRy5J1mdubcNfhLQFZdgDgyzqLNiXhX","type":"X25519KeyAgreementKey2019"}]}
    """

    val currentWorkingDir = System.getProperty("user.dir")
    val credentialsDirPath = "$currentWorkingDir/credentials"
    val keyStorePath = "$currentWorkingDir/cert/webWallet/webWallet.p12"
    
    // GLOBAL

    var challenge = ""
    var last_vp_token: String? = null
    var last_authorization_request: AuthorizationRequest? = null


    init {
        VDR.initialize()
        if(VDR.getValue(WALLET_DID)==null){
            VDR.setValue(WALLET_DID,DOC)  
        }  
    }



    override fun run() {
        runBlocking {
            var keyStoreFile = File(keyStorePath)
            val keyStorePassword = ""
            val privateKeyPassword = ""
            val keyAlias = "webWallet"
            val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
            keyStore.load(FileInputStream(keyStoreFile), keyStorePassword.toCharArray())
 
            val environment = applicationEngineEnvironment {
                log = LoggerFactory.getLogger("ktor.application")
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
                            call.respond(types.toString())
                            client.close()
                        }

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

                            call.respond(uri)
                            client.close()
                        }




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
                            println(auth_code)
                            // ACCESS TOKEN
                            val token = get_Access_Token(client, auth_code, challenge, clientID, clientSecret,"example.com")
                            
                            // CREDENTIAL
                            val credential = getCredential(client, token)  
                            
                            call.respond(credential)
                            client.close()
                        }



                        get("/listCredentials"){
                            call.respond(listCredential())
                        }

                        post("/storeCredential"){
                            val parameters = call.receiveParameters()
                            val credential = parameters["credential"]
                            val name = parameters["nameCred"]
                            if (credential == null || name == null) throw IllegalArgumentException("Invalid parameters")

                            saveCredential(credential,name)
                        }

                        post("/deleteCredential"){
                            val parameters = call.receiveParameters()

                            val name = parameters["nameCred"]
                            if (name == null) throw IllegalArgumentException("Invalid parameters")

                            val b = deleteFile(name)
                        }

                        get("/validCredentials"){
                            val client = HttpClient() {
                                install(ContentNegotiation) { json() }
                                expectSuccess = false
                            }


                            val list = obtainValidCredentialsDemo(client)
                            call.respond(list)

                            client.close()
                        }

                        post("/selectCredential") {
                            // Recibir el cuerpo de la solicitud como texto plano
                            val credential = call.receiveText()
                            if (credential.isEmpty()) throw IllegalArgumentException("Invalid parameters")
                        
                            val client = HttpClient() {
                                install(ContentNegotiation) { json() }
                                expectSuccess = false
                            }
                            val result = verifyPresentation(client, credential)
                            call.respond(result)
                        
                            client.close()
                        }     
                    }

                }
            }

            embeddedServer(Netty, environment).start(wait = true)
        }
    }


    suspend fun getCredential(client: HttpClient, tokenResponse: String): String {
        println("")
        println(verde+"[+] Wallet: GET credential"+reset)
        println("")

        val jsonElement = JsonParser.parseString(tokenResponse)
        if (!jsonElement.isJsonObject) throw IllegalArgumentException("Invalid JSON response")

        val jsonObject = jsonElement.asJsonObject
        val accessToken = jsonObject["access_token"]?.asString ?: throw IllegalArgumentException("Access token not found")
        val cNonce = jsonObject["c_nonce"]?.asString ?: throw IllegalArgumentException("c_nonce not found")


        val signedJWT = generateDidProof(cNonce)
        println("Proof: "+signedJWT)
    
        val response = client.post(ENDPOINT_CREDENTIAL) {
            header(HttpHeaders.Authorization, "Bearer $accessToken")
            
            setBody(FormDataContent(Parameters.build {
                append("proof", signedJWT)
            }))
        }
        val credential = response.bodyAsText()
        println("Credential: "+credential)
        return credential
    }
    
    
    

suspend fun get_Access_Token(client: HttpClient, authCode: String, code: String, clientId: String, clientSecret: String, redirectUri: String): String {
    println("")
    println(verde+"[+] Wallet: GET access Token"+reset)
    println("")

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
    println("Access token: "+token)
    return token
}

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

    suspend fun push_credential_parameters(client: HttpClient, challenge: String, clientId: String, type: String): String {

        println("")
        println(verde + "[+] Wallet: PUSH credential parameters request" + reset)
        println("")

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


    suspend fun get_OIDC_discovery_document(client: HttpClient, endpoint: String): MutableList<String>{
        
        val issuer = OIDC4CIService.getWithProviderMetadata(OIDCProvider(endpoint, endpoint))
        val supportedCredentialsList = mutableListOf<String>()
        OIDC4CIService.getSupportedCredentials(issuer).forEach { supported_cred ->
            supportedCredentialsList.add(supported_cred.key)
        }
        return  supportedCredentialsList;
    }


    suspend fun obtainValidCredentialsDemo(client: HttpClient): String {

        println("\n$verde[+] Wallet: Obtain valid credentials $reset\n")

        val req = OIDC4VPService.parseOIDC4VPRequestUri(URI.create(last_vp_token))
        if (req == null){
            println("Error parsing SIOP request")
            return """{"error": "Error parsing SIOP request"}"""
        }
        val presentationDefinition = OIDC4VPService.getPresentationDefinition(req)
        last_authorization_request = req
        val list = extractPresentationDefinitionInfo(KlaxonWithConverters().toJsonString(presentationDefinition))

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

    suspend fun verifyPresentation(client: HttpClient, credential: String): Boolean {

        println("\n$verde[+] Wallet: Creating a VP $reset\n")

        val presentation = createVerifiablePresentation(credential).toVerifiablePresentation()
        if (last_authorization_request == null) return false
        val resp = OIDC4VPService.getSIOPResponseFor(last_authorization_request!!, WALLET_DID, listOf(presentation))
        val url2 = "http://oidc4vp-proxy:8080"+"/ngsi-ld/v1/entities/urn:a.*"
        val result = OIDC4VPService.postSIOPResponse_UMU(last_authorization_request!!, resp, CompatibilityMode.OIDC, "GET", url2, "requester de ejemplo")
        println(result)
        return true
    }

    fun createVerifiablePresentation(credential: String): String {
        try {     
            val presentableCredentials = listOf(credential.toPresentableCredential())
    
            val presentation = jsonLdCredentialService.present(
                vcs = presentableCredentials,
                holderDid = WALLET_DID,
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


    fun generateDidProof(nonce: String): String {
        val payload = buildJsonObject {
            put("iss", WALLET_DID)
            put("aud", "https://server.example.com") 
            put("c_nonce", nonce)
            put("exp", (System.currentTimeMillis() / 1000))
        }.toString()
        
        val signedJWT = jwtService.sign(KEY_ALIAS, payload) 
        return signedJWT
    }

    fun saveCredential(credential:String, name:String) {
        println("\n$verde[+] Wallet: Save credential $reset\n")
        val cred = credential.toVerifiableCredential()
        Custodian.getService().storeCredential(name, cred)
    }

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






    fun generarStateAleatorio(): String {
        val secureRandom = SecureRandom()
        val bytes = ByteArray(32)
        secureRandom.nextBytes(bytes)

        val base64String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        val state = base64String.substring(0, 16) + "-" + base64String.substring(16)
        
        return state
    }

    fun String.sha256(): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(this.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun extractPresentationDefinitionInfo(json: String):List<VerifiableCredential> {
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


         return verifyCredentials(credentialTypes,paths ,credentialSubjectAttributes)
    }
    
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
}

