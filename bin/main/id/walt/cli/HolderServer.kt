package id.walt.cli

import com.github.ajalt.clikt.core.CliktCommand
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.runBlocking
import java.net.URI
import id.walt.services.oidc.OIDC4CIService
import java.security.SecureRandom
import com.google.gson.Gson
import id.walt.model.oidc.*
import id.walt.services.key.KeyService
import java.util.*
import java.net.URLEncoder
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import io.ktor.client.request.forms.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.add
import kotlinx.serialization.json.jsonObject
import id.walt.services.jwt.WaltIdJwtService
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.JsonPrimitive
import id.walt.services.oidc.OIDC4VPService
import id.walt.common.KlaxonWithConverters
import id.walt.services.did.DidService
import id.walt.credentials.w3c.toVerifiablePresentation
import id.walt.services.oidc.CompatibilityMode
import id.walt.common.prettyPrint
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths
import id.walt.custodian.Custodian
import id.walt.credentials.w3c.toVerifiableCredential

import id.walt.model.oidc.CredentialClaim
import id.walt.services.context.ContextManager
import id.walt.services.vc.JsonLdCredentialService
import id.walt.credentials.w3c.PresentableCredential
import id.walt.credentials.w3c.toPresentableCredential

/* SSIKIT Holder */
class Holder :
        CliktCommand(
                name = "holder",
                help =
                        """Example of credential issuance flow.
         """
        ) {

        private val jsonLdCredentialService = JsonLdCredentialService.getService()

        // ENDPOINTS ISSUER
        val ENDPOINT_LIST_CREDENTIALS = "https://localhost:8443/list"
        val ENDPOINT_AUTH = "https://localhost:8443/auth"
        val ENDPOINT_CODE = "https://localhost:8443/code"
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
        val ISSUER_DID = "did:key:z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc"
        val KEY_ALIAS = "131ae91a20504a8b8b8a7dbce1660a61"

        val currentWorkingDir = System.getProperty("user.dir")
        val credentialsDirPath = "$currentWorkingDir/credentials"

        // Servicios
        private val keyService = KeyService.getService()
    
        override fun run() = runBlocking {

            val client =
                    HttpClient() {
                        install(ContentNegotiation) { json() }
                        expectSuccess = false
                    }

            println("")
            println(verde+"[+] Select an action: "+reset)
            println("1 - Issue a verifiable credential")
            println("2 - Generate and verify a verifiable presentation")
            

            print("Option: ")
            val opt = readLine()!!
            println("")
            
            if (opt == "1")
            {
                println("")
                println(verde+"[+] Introduce a new Username and Password"+reset)
                println("")
                            
                print("Username: ")
                val user = readLine()!!
                print("Password: ")
                val pass = readLine()!!
    
                try{
    
                    // REGISTER
                    val registerResponse = registerUser(client, user, pass)
                    println("Register Response: ${registerResponse.status}, Body: ${registerResponse.bodyAsText()}")
    
                    //LOGIN
                    val (clientID, clientSecret) = loginUser(client, user, pass)
    
                    if (clientID == "" || clientSecret == "") {
                        println(rojo+"[!] Invalid ClientID or clienSecret"+reset)
                        throw IllegalArgumentException("Invalid ClientID or clienSecret")
                    }
    
                    // METADATA
                    val credentialType = get_OIDC_discovery_document(client)
    
                    // AUTH
                    val challenge = generarStateAleatorio()
                    val auth_code = push_OIDC_auth_request(client, challenge, clientID, credentialType)
    
                    // ACCESS TOKEN
                    val token = get_Access_Token(client, auth_code, challenge, clientID, clientSecret,"example.com")
                    
                    // CREDENTIAL
                    val credential = getCredential(client, token)       
                    
                    saveCredential(credential)
                    client.close()
    
                } catch (e: Exception) {
                    println(rojo + "[!] Error: ${e.message}" + reset)
                }
            }

            else if (opt == "2"){
                try{

                    val response = verify(client)
                    client.close()
    
                } catch (e: Exception) {
                    println(rojo + "[!] Error: ${e.message}" + reset)
                }
            }
               
            

        }

        suspend fun getCredential(client: HttpClient, tokenResponse: String): String {
            println("")
            println(verde+"[+] GET credential"+reset)
            println("")

            print("Credential to sign: ")
            val credentialData = readLine()!!

        
            val jsonElement = Json.parseToJsonElement(tokenResponse)
            if (jsonElement !is JsonObject) throw IllegalArgumentException("Invalid JSON response")

            val accessToken = jsonElement.jsonObject["access_token"]?.toString()?.removeSurrounding("\"") ?: throw IllegalArgumentException("Access token not found")
            val cNonce = jsonElement.jsonObject["c_nonce"]?.toString()?.removeSurrounding("\"") ?: throw IllegalArgumentException("c_nonce not found")
            


            val signedJWT = generateDidProof(cNonce)
            println("Proof: "+signedJWT)
        
            val response = client.post(ENDPOINT_CREDENTIAL) {
                header(HttpHeaders.Authorization, "Bearer $accessToken")
                
                setBody(FormDataContent(Parameters.build {
                    append("proof", signedJWT)
                    append("credential", credentialData)

                }))
            }
            val credential = response.bodyAsText()
            println("Credential: "+credential)
            return credential
        }
        
        
        

    suspend fun get_Access_Token(client: HttpClient, authCode: String, code: String, clientId: String, clientSecret: String, redirectUri: String): String {
        println("")
        println(verde+"[+] GET access Token"+reset)
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
            val jsonElement = Json.parseToJsonElement(responseBody)
            if (jsonElement is JsonObject) {
                val clientId = jsonElement.jsonObject["clientId"]?.toString()?.removeSurrounding("\"") 
                val clientSecret = jsonElement.jsonObject["clientSecret"]?.toString()?.removeSurrounding("\"") 
                if (clientId != null && clientSecret != null) {
                    return Pair(clientId, clientSecret)
                }
            }
        }
        return Pair("","")
    }
    

    suspend fun push_OIDC_auth_request(client: HttpClient, challenge: String, clientId: String, type: String): String {

        println("")
        println(verde + "[+] PUSH OIDC auth request" + reset)
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
            val code: String = response.bodyAsText()
            println("auth_code: "+ code)
            return code
        } else {
            println(rojo + "[!] Error: ${response.status.description}" + reset)
            throw Exception("Error during OIDC auth request: ${response.status.description}")
        }
    }
    

    suspend fun get_OIDC_discovery_document(client: HttpClient): String{
        println("")
        println(verde+"[+] GET OIDC discovery document"+reset)
        println("")

        
        val issuer = OIDC4CIService.getWithProviderMetadata(OIDCProvider(ENDPOINT_LIST_CREDENTIALS, ENDPOINT_LIST_CREDENTIALS))

        println("---")
        var x = 0
        OIDC4CIService.getSupportedCredentials(issuer).forEach { supported_cred ->
            println("Issuable credentials:")
            println("${x}- ${supported_cred.key}")
            println("---")
            x++
        }

        print("Selecciona que tipo de credencial deseas crear: ")
        val credentialTypes = readLine()
        //val credentialTypes="VerifiableId"
        println("")
        println(verde+"[+] Credential selected -> ${credentialTypes}"+reset)
        println("")

        return credentialTypes.toString()
    }


    fun generateDidProof(nonce: String): String {
        val payload = buildJsonObject {
            put("iss", ISSUER_DID)
            put("aud", "https://server.example.com") 
            put("c_nonce", nonce)
            put("exp", (System.currentTimeMillis() / 1000))
        }.toString()
        
        val signedJWT = jwtService.sign(KEY_ALIAS, payload) 
        return signedJWT
    }

    fun saveCredential(credential:String) {

        print("Por favor, ingrese el nombre bajo el cual desea guardar la credencial:")
        val name = readLine() ?: "example"
        val credentialFilePath = Paths.get(credentialsDirPath, "$name.jsonld")
        Files.write(credentialFilePath, credential.toByteArray())
        println("")
        println(verde+"The credential has been successfully stored in ${credentialFilePath}"+reset)
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

    fun selectCredential(): String {
        val credentialsDir = File(credentialsDirPath.toString())
        val credentialFiles = credentialsDir.listFiles { _, name -> name.endsWith(".jsonld") }
    
        if (credentialFiles != null && credentialFiles.isNotEmpty()) {

            println("")
            println(verde+"[+] Select the credential:"+reset)
            println("")
    
            // Mostrar los archivos con un índice
            credentialFiles.forEachIndexed { index, file ->
                println("${index + 1}-${file.name}")
            }
    
            print("Option: ")
            val option = readLine()?.toIntOrNull()
    
            if (option != null && option in 1..credentialFiles.size) {
                val selectedFile = credentialFiles[option - 1]
                println("You have selected: ${selectedFile.name}")
                return selectedFile.name
            } else {
                println("Invalid option selected.")
                return ""
            }
        } else {
            println("No credentials found in the directory.")
            return ""
        }
    }

    fun createVerifiablePresentation(credentialPath: String, holderDid: String): String {
        try {
            val credentialContent = Files.readString(Paths.get(credentialPath))        
            val presentableCredentials = listOf(credentialContent.toPresentableCredential())
    
            val presentation = jsonLdCredentialService.present(
                vcs = presentableCredentials,
                holderDid = holderDid,
                domain = null, // Opcional: especificar si es necesario
                challenge = null, // Opcional: especificar si es necesario
                expirationDate = null // Opcional: especificar si es necesario
            )
            
            return presentation
        } catch (e: Exception) {
            e.printStackTrace()
            return "Error creating the verifiable presentation: ${e.message}"
        }
        
        
    }
    

    suspend fun verify(client: HttpClient): String {

        val credential = selectCredential()
        val presentation = createVerifiablePresentation(credentialsDirPath+"/"+credential, ISSUER_DID).toVerifiablePresentation()

        println("")
        println("")
        println(presentation)
        println("")
        println("")

        val url = URLBuilder(ENDPOINT_OBTAIN_VP).apply {
            parameters.append("Device", "http://oidc4vp-proxy:8080")
        }.buildString()
    
        val res: HttpResponse = client.get(url)
        val locationHeader = res.headers["Location"] 
        println(locationHeader ?: "No location header found")

        val req = OIDC4VPService.parseOIDC4VPRequestUri(URI.create(locationHeader))
        
        if (req == null){
            println("Error parsing SIOP request")
            return "Error"
        }
        
        val presentationDefinition = OIDC4VPService.getPresentationDefinition(req)
        println("Presentation requirements: ${KlaxonWithConverters().toJsonString(presentationDefinition)}")

        
        val did = "did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK"

        val resp = OIDC4VPService.getSIOPResponseFor(req, did, listOf(presentation))

        println("Presentation response: ${resp.toFormParams()}")
        val url2 = "http://oidc4vp-proxy:8080"+"/ngsi-ld/v1/entities/urn:a.*"
        val result = OIDC4VPService.postSIOPResponse_UMU(req, resp, CompatibilityMode.OIDC, "GET", url2, "requester de ejemplo")

        println("\nRespuesta final recibida: $result")
    
        return result
    }
    
}