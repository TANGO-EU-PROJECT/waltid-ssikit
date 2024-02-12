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

/* SSIKIT Holder */
class Holder :
        CliktCommand(
                name = "holder",
                help =
                        """Example of credential issuance flow.
         """
        ) {

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

        // Servicios
        private val keyService = KeyService.getService()
    
        override fun run() = runBlocking {

            val client =
                    HttpClient() {
                        install(ContentNegotiation) { json() }
                        expectSuccess = false
                    }
               
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

                val response = verify(client)
        
                client.close()

            } catch (e: Exception) {
                println(rojo + "[!] Error: ${e.message}" + reset)
            }

        }

        suspend fun getCredential(client: HttpClient, tokenResponse: String): String {
            println("")
            println(verde+"[+] GET credential"+reset)
            println("")
        
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

    suspend fun verify(client: HttpClient): String {
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


        val vp = """
            {"type":["VerifiablePresentation"],"@context":["https://www.w3.org/2018/credentials/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"urn:uuid:06e65e61-4019-4a73-9930-31bd56556755","holder":"did:key:z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc","verifiableCredential":[{"type":["VerifiableCredential","VerifiableAttestation","ProofOfResidence"],"@context":["https://www.w3.org/2018/credentials/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"urn:uuid:fd30949d-1348-443c-ae6e-d9385f3db926","issuer":"did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK","issuanceDate":"2024-02-11T17:17:20Z","issued":"2024-02-11T17:17:20Z","validFrom":"2024-02-11T17:17:20Z","expirationDate":"2022-06-22T14:11:44Z","proof":{"type":"JsonWebSignature2020","creator":"did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK","created":"2024-02-11T17:17:20Z","proofPurpose":"assertionMethod","verificationMethod":"did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK#z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK","jws":"eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJFZERTQSJ9..IkE-x0J5MCh4RZQbcFgkdDNung6SefLCdjvpT9JnAmYA1FG5VMGZVrjNqh_We84GlTGt5m7GGNxYKBeycXTiBw"},"credentialSchema":{"id":"https://raw.githubusercontent.com/walt-id/waltid-ssikit-vclib/master/src/test/resources/schemas/ProofOfResidence.json","type":"JsonSchemaValidator2018"},"credentialSubject":{"id":"did:key:z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc","address":{"countryName":"LU","locality":"Steinfort","postalCode":"L-8410","streetAddress":"16RouteD'Arlon"},"dateOfBirth":"1993-04-08","familyName":"Beron","familyStatus":"Single","firstNames":"Domink","gender":"Male","identificationNumber":"123456789","nationality":"AT"},"credentialStatus":{"id":"https://essif.europa.eu/status/identity#verifiableID#1dee355d-0432-4910-ac9c-70d89e8d674e","type":"CredentialStatusList2020"},"evidence":[{"documentPresence":"Physical","evidenceDocument":"Passport","id":"https://essif.europa.eu/tsr-va/evidence/f2aeec97-fc0d-42bf-8ca7-0548192d5678","subjectPresence":"Physical","type":["DocumentVerification"],"verifier":"did:ebsi:2962fb784df61baa267c8132497539f8c674b37c1244a7a"}],"title":"ProofofResidence"}],"proof":{"type":"JsonWebSignature2020","creator":"did:key:z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc","created":"2024-02-11T17:19:49Z","proofPurpose":"authentication","verificationMethod":"did:key:z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc#z6MkrNgKbTBGKXaGo6mjrJit9qcv4S552wgHGq1xZD6JrCCc","jws":"eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJFZERTQSJ9..V7MSHVJrUQoATocL6lU6M5TA-qtQ905aLgStyOlE_bkPJmbjQyx-1yL2p84orqGedX6AyKbrNMQ8KrJnuVKiAA"}}
        """.toVerifiablePresentation()

        val resp = OIDC4VPService.getSIOPResponseFor(req, did, listOf(vp))

        println("Presentation response: ${resp.toFormParams()}")
        val url2 = "http://oidc4vp-proxy:8080"+"/ngsi-ld/v1/entities/urn:a.*"
        val result = OIDC4VPService.postSIOPResponse_UMU(req, resp, CompatibilityMode.OIDC, "GET", url2, "requester de ejemplo")

        println("\nRespuesta final recibida: $result")
    
        return result
    }
    
}