package id.walt.cli

import com.github.ajalt.clikt.core.CliktCommand
import io.ktor.server.application.*
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.receiveText
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.http.content.TextContent
import java.net.URI
import java.security.SecureRandom
import java.io.File
import java.nio.charset.Charset
import java.util.UUID
import java.time.Instant
import java.util.Base64
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.interfaces.DecodedJWT
import id.walt.model.credential.status.CredentialStatus
import id.walt.sdjwt.DecoyMode
import id.walt.sdjwt.SDMap
import id.walt.signatory.Ecosystem
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import id.walt.signatory.Signatory
import io.ktor.server.netty.*
import id.walt.services.ecosystems.fabric.VDR
import com.nimbusds.jwt.SignedJWT 
import id.walt.sdjwt.JwtVerificationResult
import id.walt.crypto.*
import id.walt.model.DidUrl
import id.walt.services.did.DidService
import id.walt.services.key.KeyService
import com.nimbusds.jose.crypto.*
import org.bouncycastle.asn1.ASN1Sequence
import id.walt.services.jwt.JwtService
import org.bouncycastle.asn1.ASN1BitString;
import java.util.*
import com.nimbusds.jwt.JWTClaimsSet
import io.ktor.network.tls.certificates.generateCertificate
import io.ktor.server.engine.*
import io.ktor.network.tls.certificates.*
import java.security.KeyStore
import java.io.FileInputStream
import org.slf4j.LoggerFactory
import kotlinx.coroutines.runBlocking
import java.nio.charset.StandardCharsets
import java.net.URLEncoder
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
import kotlinx.serialization.Serializable
import com.google.gson.JsonObject
import io.ktor.server.application.*
import io.ktor.server.http.content.*
import io.ktor.server.plugins.cors.*
import java.nio.file.Files
import java.nio.file.Paths

/* SSIKIT issuer */
class IssuerCommand :
        CliktCommand(
                name = "issuer",
                help =
                        """
                        OIDC4VC issuer
                """
        ) {
            data class AuthRequest(val codeVerifier: String, val code: String, val type: String, val credentialSubject: Map<String, Any>)
            data class TokenInfo(val bearer: String, val nonce: String ,val expirationTime: Instant)

            val authRequestRegistry = mutableMapOf<String, AuthRequest>()
            val clientID = mutableMapOf<String, String>()
            val clientCredentials = mutableMapOf<String, String>()
            val tokenRegistry = mutableMapOf<String, TokenInfo>()

            val logs: Boolean = System.getenv("logs").toBoolean()

            val DID_BACKEND = "did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK"
            val KEY_ALIAS = "e278cdfd6656431fb2125a7cf1b23104"
            val DOC = """
            {"assertionMethod":["did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK#z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK"],"authentication":["did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK#z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK"],"capabilityDelegation":["did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK#z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK"],"capabilityInvocation":["did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK#z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK"],"@context":"https://www.w3.org/ns/did/v1","id":"did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK","keyAgreement":["did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK#z6LSgGuxWYs6ea3ZBNSrzrPY5LxZYSjKNyTZwHUDkwxhaWAH"],"verificationMethod":[{"controller":"did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK","id":"did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK#z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK","publicKeyBase58":"Eobb9nZ8Ve53rxyMjxYBHV7bf2NMb4f83JcAq91NwTtw","type":"Ed25519VerificationKey2019"},{"controller":"did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK","id":"did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK#z6LSgGuxWYs6ea3ZBNSrzrPY5LxZYSjKNyTZwHUDkwxhaWAH","publicKeyBase58":"5bjnzF4EZ7Kp5z56UCsakkk5hJCCgNHR4JkYGVKAs8PX","type":"X25519KeyAgreementKey2019"}]}
            """

            val keyService = KeyService.getService()
            val jwtService = WaltIdJwtService()
            val currentWorkingDir = System.getProperty("user.dir")
            val keyStorePath = "$currentWorkingDir/cert/issuer/issuer.p12"

            //Salida mas legible
            val verde = "\u001B[32m"
            val rojo = "\u001B[31m"
            val reset = "\u001B[0m"

            init {
                VDR.initialize()
                if(VDR.getValue(DID_BACKEND)==null){
                    VDR.setValue(DID_BACKEND,DOC)  
                }  
            }

            override fun run() {
                runBlocking {
                    var keyStoreFile = File(keyStorePath)
                    
                    val keyStorePassword = ""
                    val privateKeyPassword = ""
                    val keyAlias = "issuer"
                    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
                    keyStore.load(FileInputStream(keyStoreFile), keyStorePassword.toCharArray())
                    
                    val environment = applicationEngineEnvironment {
                        log = LoggerFactory.getLogger("ktor.application")
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


                            install(CORS) {
                                allowCredentials = true
                                allowNonSimpleContentTypes = true
                                allowSameOrigin = true
                                allowHost("localhost:8445", schemes = listOf("https"))
                                allowHost("localhost:8444", schemes = listOf("https"))
                                allowHost("localhost:8443", schemes = listOf("https"))
                                allowHost("umu-webwallet:8445", schemes = listOf("https"))
                                allowHost("umu-verifier:8444", schemes = listOf("https"))
                                allowHost("umu-issuer:8443", schemes = listOf("https"))
                                allowHost("", schemes = listOf("https")) 
                                allowHeader(HttpHeaders.ContentType)
                            }
                            
                            routing {

                                    static("/static") {
                                        resources("static")
                                    }
            

                                
                                    post("/registerBackend") {

                                        println("")
                                        println(verde+"[+] Issuer: Register a user."+reset)
                                        println("")

                                        val parameters = call.receiveParameters()
                                        val user = parameters["user"]
                                        val pass = parameters["pass"]

                                        if (logs){
                                            println("")
                                            println(rojo+"[!] Issuer logs: username - "+user+" password - "+pass+reset)
                                            println("")
                                        }

                                        if (clientCredentials.containsKey(user)) {
                                            call.respondText("This username is already registered.")
                                        } else {
                                            if (user != null && pass != null) {
                                                clientCredentials[user] = pass
                                            } else {
                                                call.respond(HttpStatusCode.BadRequest, "Username and password fields are required")
                                            }
                                            call.respondText("The user registered successfully.")
                                        }
                                    }
                        
                                    post("/loginBackend") {

                                        println("")
                                        println(verde+"[+] Issuer: Log in a user."+reset)
                                        println("")

                                        val parameters = call.receiveParameters()
                                        val user = parameters["user"]
                                        val pass = parameters["pass"]

                                        if (logs){
                                            println("")
                                            println(rojo+"[!] Issuer logs: username - "+user+" password - "+pass+reset)
                                            println("")
                                        }

                                        if (clientCredentials[user] == pass) {

                                            val clientId = UUID.randomUUID().toString()
                                            val clientSecret = UUID.randomUUID().toString()
                                            clientID[clientId] = clientSecret
                                            val jsonResponse = "{\"clientId\":\"$clientId\", \"clientSecret\":\"$clientSecret\"}"
                                            call.respondText(jsonResponse, ContentType.Application.Json)

                                        } else {
                                            call.respondText("Invalid username or password.", status = io.ktor.http.HttpStatusCode.Unauthorized)
                                        }
                                    }
    
    
                                    get("/list/.well-known/openid-configuration"){
    
                                        println("")
                                        println(verde+"[+] Issuer: GET OIDC discovery document"+reset)
                                        println("")
    
                                        val jsonFilePath_ProofOfResidence = "src/main/resources/server/credentialJSON/ProofOfResidence.json"
                                        val jsonFilePath_VerifiableVaccinationCertificate = "src/main/resources/server/credentialJSON/VerifiableVaccinationCertificate.json"
                                        val jsonFilePath_VerifiableDiploma = "src/main/resources/server/credentialJSON/VerifiableDiploma.json"
                                        val jsonFilePath_OpenBadgeCredential = "src/main/resources/server/credentialJSON/OpenBadgeCredential.json"
                                        val jsonFilePath_Europass = "src/main/resources/server/credentialJSON/Europass.json"
                                        val jsonFilePath_VerifiableId = "src/main/resources/server/credentialJSON/VerifiableId.json"
                                        val jsonFilePath_ParticipantCredential = "src/main/resources/server/credentialJSON/ParticipantCredential.json"
    
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
    
    
                                        var credentials = """{"authorization_endpoint": "https://localhost:8443/auth", "token_endpoint": "https://localhost:8443/token", "pushed_authorization_request_endpoint": "https://localhost:8443/par", "issuer": "https://localhost:8443", "jwks_uri": "https://issuer.walt.id/issuer-api/default/oidc", "grant_types_supported": ["authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code"], "request_uri_parameter_supported": true, "credentials_supported": { """
                                        //credentials = credentials + jsonContent_ProofOfResidence + "," + jsonContent_VerifiableVaccinationCertificate + "," + jsonContent_VerifiableDiploma + "," + jsonContent_OpenBadgeCredential + "," + jsonContent_Europass + "," + jsonContent_VerifiableId + "," + jsonContent_ParticipantCredential + "},"
                                        credentials = credentials + jsonContent_ProofOfResidence + "," + jsonContent_VerifiableId + "," + jsonContent_ParticipantCredential + "},"
                                        
                                        credentials = credentials + """ "credential_issuer": {"display" : [{"locale" : null, "name" : "https://localhost:8443/"}]}, "credential_endpoint": "https://localhost:8443/credential", "subject_types_supported": ["public"]} """
                                        
                                        if (logs){
                                            println("")
                                            println(rojo+"[!] Issuer logs: Metadata - "+credentials+reset)
                                            println("")
                                        }
                                        
                                        call.respond(credentials)
                                    }
    

                                    get("/auth") {
                                        println("")
                                        println(verde + "[+] Issuer: PUSH OIDC auth request" + reset)
                                        println("")
                                    
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

                                            val code = generarValorAleatorio()
                                            authRequestRegistry[clientId] = AuthRequest(codeChallenge.sha256(), code, t, mutableMapOf<String, Any>())
                                            

                                            val locationUri = StringBuilder()
                                            locationUri.append("https://umu-webWallet:8445/form")
                                            locationUri.append("?clientId=$clientId")
                                            locationUri.append("&template=$t") 

                                            if (logs){
                                                println("")
                                                println(rojo+"[!] Issuer logs: locationUri - "+locationUri.toString()+reset)
                                                println("")
                                            }
                                            
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
                                            
                                            println("template: "+ template)
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
                                    
                                            authRequestRegistry[clientId] = AuthRequest(authRequest.codeVerifier, authRequest.code, type, credentialSubjectMap)
                                    
                                            if (logs) {
                                                println("\n$rojo[!] Issuer logs: authCode - ${authRequest.code}$reset\n")
                                            }
                                    
                                            call.respond(authRequest.code)
                                        } catch (e: IllegalArgumentException) {
                                            println("$rojo[!] Error: ${e.message}$reset")
                                            call.respond(HttpStatusCode.BadRequest, mapOf("error" to e.message))
                                        } catch (e: Exception) {
                                            println("$rojo[!] Unexpected Error: ${e.localizedMessage}$reset")
                                            call.respond(HttpStatusCode.InternalServerError, mapOf("error" to "An unexpected error occurred."))
                                        }
                                    }
                                    

                                    post("/token") {

                                        println("")
                                        println(verde + "[+] Issuer: PUSH OIDC access token request" + reset)
                                        println("")

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
                            
                                        println("auth.code: "+authRequestInfo!!.code)
                                        println("code: "+code)
                                        println("auth.ver: "+authRequestInfo!!.codeVerifier)
                                        println("ver: "+codeVerifier)

                                        if (!(authRequestInfo != null && 
                                            authRequestInfo.code == code &&
                                            authRequestInfo.codeVerifier == codeVerifier)) 
                                        {
                                            call.respond(HttpStatusCode.BadRequest, "Invalid code or code_verifier")
                                            return@post
                                        }
                                
                                        val accessToken = accessTokenResponse(clientId, authRequestInfo!!.type)

                                        if (logs){
                                            println("")
                                            println(rojo+"[!] Issuer logs: accessToken - "+accessToken+reset)
                                            println("")
                                        }
                                        call.respond(accessToken)

                                    }
                                

    
                                    post("/credential"){
                                        println("")
                                        println(verde+"[+] Issuer: Get credential from issuer."+reset)
                                        println("")

                                        try{

                                            val parameters = call.receiveParameters()
                                            val proof = parameters["proof"]?: ""
                                            val authorizationHeader = call.request.headers["Authorization"]?: ""
                                            val authorization = authorizationHeader.substringAfter("Bearer ", "")




                                            val clientId = getValueFromJWT(authorization, "client_id")
                                            val subjectDid = getValueFromJWT(proof, "iss")

                                            if (!isAccessTokenValid(authorization)) throw IllegalArgumentException("The authorization header isn't valid.")
                                            if (!isProofValid(proof,clientId)) throw IllegalArgumentException("The proof isn't valid.")

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
                                    

                                            val ldSignatureType: LdSignatureType? = null
                                            val issuerVerificationMethod: String? = null
                                            val credentialTypes: CredentialStatus.Types? = null
                                            val selectiveDisclosurePaths: List<String>? = null

                                            val credential_signed = CreateCredential(DID_BACKEND,subjectDid,credential, issuerVerificationMethod, ProofType.LD_PROOF, "assertionMethod", ldSignatureType, Ecosystem.DEFAULT , credentialTypes, DecoyMode.NONE, 0, selectiveDisclosurePaths)
                                            
                                            if (logs){
                                                println("")
                                                println(rojo+"[!] Issuer logs: Credential - "+credential_signed+reset)
                                                println("")
                                            }
                                            
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


            fun getValueFromJWT(jwt: String, v: String): String {
                val parts = jwt.split(".")
                val payload = parts[1]
                val decodedPayload = String(Base64.getDecoder().decode(payload))
                val jsonElement = Json.parseToJsonElement(decodedPayload)
                val content = jsonElement.jsonObject[v]?.toString()?.removeSurrounding("\"") ?: throw IllegalArgumentException("Error processing the JWT.")
                return content
            }

            fun isProofValid(proof: String, clientId: String): Boolean {
                val tokenInfo = tokenRegistry[clientId] ?: return false 
                val c_nonce = getValueFromJWT(proof, "c_nonce")

                if (c_nonce != tokenInfo.nonce) return false

                val verificationResult = JwtService.getService().verify(proof)

                return verificationResult.verified
            }
            

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
                if (!JwtService.getService().verify(jwt).verified) return false 
            
                val currentTime = Instant.now()
                if (tokenInfo.expirationTime.isBefore(currentTime)) return false 
            
                return true
            }
            

              
            fun isTokenValid(token: String): Boolean {
                val tokenInfo = tokenRegistry[token] ?: return false 
                
                
                val currentTime = Instant.now()
                return currentTime.isBefore(tokenInfo.expirationTime) 
            }
            

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




            fun CreateCredential(issuerDid: String, subjectDid: String, template: String, issuerVerificationMethod: String?, proofType: ProofType, proofPurpose: String, ldSignatureType: LdSignatureType?, ecosystem: Ecosystem , statusType: CredentialStatus.Types?, decoyMode: DecoyMode, numDecoys: Int, selectiveDisclosurePaths: List<String>?): String {
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

            fun String.sha256(): String {
                val bytes = MessageDigest.getInstance("SHA-256").digest(this.toByteArray(Charsets.UTF_8))
                return bytes.joinToString("") { "%02x".format(it) }
            }

            fun generarValorAleatorio(): String {
                val secureRandom = SecureRandom()
                val bytes = ByteArray(32)
                secureRandom.nextBytes(bytes)
        
                val base64String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
            
                val state = base64String.substring(0, 16) + "-" + base64String.substring(16)
                
                return state
            }

            fun decodeBasicAuth(authHeader: String): Pair<String, String>? {
                if (!authHeader.startsWith("Basic ")) return null
                val base64Credentials = authHeader.removePrefix("Basic ")
                val credentials = String(Base64.getDecoder().decode(base64Credentials), Charsets.UTF_8)
                val clientIdSecret = credentials.split(":", limit = 2)
                if (clientIdSecret.size != 2) return null 
            
                return Pair(clientIdSecret[0], clientIdSecret[1])
            }
        }
