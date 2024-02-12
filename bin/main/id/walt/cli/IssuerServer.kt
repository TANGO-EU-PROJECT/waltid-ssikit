package id.walt.cli

import com.github.ajalt.clikt.core.CliktCommand
import io.ktor.server.application.*
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.receiveText
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.http.HttpStatusCode
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



/* SSIKIT issuer */
class IssuerCommand :
        CliktCommand(
                name = "issuer",
                help =
                        """
                        Servidor HTTP para el Relying Party (Issuer)
                """
        ) {
            data class AuthRequest(val codeVerifier: String,val code: String)

            data class TokenRecord(val requestUri: String, val expirationTime: Instant)
            

            val authRequestRegistry = mutableMapOf<String, AuthRequest>()
            val client = mutableMapOf<String, String>()

            val tokenRegistry = mutableMapOf<String, TokenRecord>()
            val nonceRegistry = mutableMapOf<String, String>()

            val JWTRegistry = mutableSetOf<String>()


            val DID_BACKEND = "did:key:z6MksxnpdbnvDgW1idZeTAiee1Z6irjZFyzerKP1DS6degYh"
            val KEY_ALIAS = "6c5caa74bcce49eebf76744bb718c24f"
            val keyService = KeyService.getService()
            //Salida mas legible
            val verde = "\u001B[32m"
            val rojo = "\u001B[31m"
            val reset = "\u001B[0m"

            override fun run() {
                client["123456"] = "abc"
                runBlocking {
                    var keyStoreFile = File("/home/pablito/Desktop/new_ssikit/waltid-ssikit/keystore.p12")
                    val keyStorePassword = ""
                    val privateKeyPassword = ""
                    val keyAlias = "myAlias"
                    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
                    keyStore.load(FileInputStream(keyStoreFile), keyStorePassword.toCharArray())
                    
                    val environment = applicationEngineEnvironment {
                        log = LoggerFactory.getLogger("ktor.application")
                        connector {
                            port = 8099
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
                            routing {
                                
                                    post("/endpoint") {
                                        println("POST recibido")
                                    }
    
    
                                    get("/list/.well-known/openid-configuration"){
    
                                        println("")
                                        println(verde+"[+] GET OIDC discovery document"+reset)
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
                                        credentials = credentials + jsonContent_ProofOfResidence + "," + jsonContent_VerifiableVaccinationCertificate + "," + jsonContent_VerifiableDiploma + "," + jsonContent_OpenBadgeCredential + "," + jsonContent_Europass + "," + jsonContent_VerifiableId + "," + jsonContent_ParticipantCredential + "},"
                                        credentials = credentials + """ "credential_issuer": {"display" : [{"locale" : null, "name" : "https://localhost:8443/"}]}, "credential_endpoint": "https://localhost:8443/credential", "subject_types_supported": ["public"]} """
                                        println("Result: "+credentials)
                                        call.respond(credentials)
                                    }
    

                                    get("/auth") {
                                        println("")
                                        println(verde + "[+] PUSH OIDC auth request" + reset)
                                        println("")
                                    
                                        try {
                                            val responseType = call.parameters["response_type"]
                                            val clientId = call.parameters["client_id"]
                                            val codeChallenge = call.parameters["code_challenge"]
                                            val codeChallengeMethod = call.parameters["code_challenge_method"]
                                            val authorizationDetails = call.parameters["authorization_details"]
                                            val redirectUri = call.parameters["redirect_uri"]
                                    
                                            if (responseType.isNullOrEmpty() || clientId.isNullOrEmpty() || 
                                                codeChallenge.isNullOrEmpty() || codeChallengeMethod.isNullOrEmpty() ||
                                                authorizationDetails.isNullOrEmpty() || redirectUri.isNullOrEmpty()) {
                                                throw IllegalArgumentException("Missing required parameters.")
                                            }
                                    
                                            val authDetailsJson = URLDecoder.decode(authorizationDetails, StandardCharsets.UTF_8.name())
                                            val authDetails = Gson().fromJson(authDetailsJson, Map::class.java)

                                            val type = authDetails["type"] ?: throw IllegalArgumentException("Missing 'type' in 'authorization_details'.")
                                            val format = authDetails["format"] ?: throw IllegalArgumentException("Missing 'format' in 'authorization_details'.")
                                            
                                            if (!client.containsKey(clientId)) throw IllegalArgumentException("The clientID isn't valid.")
                                            if (type != "openid_credential") throw IllegalArgumentException("The type isn't valid.")
                                            if (format != "jwt_vc_json") throw IllegalArgumentException("The format isn't valid.")
                                            if (responseType != "code") throw IllegalArgumentException("The responseType isn't valid.")

                                            val code = generarValorAleatorio()
                                            authRequestRegistry[clientId] = AuthRequest(codeChallenge.sha256(), code)

                                            println("Response: $code")
                                            call.respond(code)
                                    
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

                                    post("/token") {
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
                                        } 
                                        

                                        if (!client.containsKey(clientId) || client[clientId] != clientSecret) {
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
                                
                                        println("TODO CORRECTO")
                                        //val accessToken = generateAccessToken(clientId, code)
                                
                                        //call.respond(mapOf("access_token" to accessToken, "token_type" to "Bearer"))
                                    }
                                
                                    /* 
                                    get("/token"){
                                        println("")
                                        println(verde+"[+] GET access Token"+reset)
                                        println("")
                                        var jwt = call.parameters["jwt"]
                                        if ( jwt==null || jwt.isEmpty()){
                                            call.respond("ERROR: Required parementers: JWT.")
                                            println()
                                            println(rojo+"ERROR: Required parementers: JWT."+reset)  
                                        }
                                        else{
                                            val sub = verifyAndExtractUUID(jwt)
                                            if(sub != null ){
                                                if (!JWTRegistry.contains("urn:ietf:params:oauth:request_uri:"+sub)){
                                                    call.respond("ERROR: JWT pre_auth token is already used")
                                                    println()
                                                    println(rojo+"[!] JWT pre_auth token is already used"+reset)
                                                    
                                                }
                                                else{
                                                    JWTRegistry.remove("urn:ietf:params:oauth:request_uri:"+sub)
                                                    
                                                    val bool = verificarToken("urn:ietf:params:oauth:request_uri:"+sub)
                                                    if (!bool) call.respond("ERROR: invalid or expired token.")
                                                    else{
                                                        val nonce = generarValorAleatorio()
                                                        nonceRegistry[sub] = nonce;
                                                        val token = generarAccessToken(sub,generarValorAleatorio(),nonce,construirJWT(sub))
                                                        println(token)
                                                        call.respond(token)
                                                    }
                                                }
                                            }
    
                                        }
    
                                    }
                                    */
    
                                    get("/credential"){
                                        println("")
                                        println(verde+"[+] Get credential from issuer."+reset)
                                        println("")
                                        var nonce_signed = call.parameters["nonce_signed"]
                                        var template = call.parameters["template"]
                                        var token = call.parameters["token"]
                                        //var publicKey = call.parameters["publicKey"]
    
                                        
                                        if ( template==null ||  token==null || nonce_signed==null || token.isEmpty() || nonce_signed.isEmpty() || template.isEmpty() ){
                                            call.respond("ERROR: You have to specific all the required parameters")
                                        }
                                        else{
    
                                            //Verifico que el acces token no haya expirado
                                            if(verificarToken("urn:ietf:params:oauth:request_uri:"+token)){
                                                println("template: "+template)
                                                println("token: "+token)
                                                println("nonce_signed: "+nonce_signed)
        
                                                
                                                val jwtRegex = Regex("jwt=([^)]+)")
                                                val matchResult = jwtRegex.find(nonce_signed)
                                                if (matchResult != null) {
                                                    val jwt = matchResult.groupValues[1]
                                                    val decodedJWT: DecodedJWT = JWT.decode(jwt)
                                                    val issuer = decodedJWT.issuer
                                                    val iat = decodedJWT.issuedAt
                                                    val nonce = decodedJWT.getClaim("nonce").asString()
                                                    
        
                                                    println()
                                                    println("Issuer: $issuer")
                                                    println("IAT (Issued At): $iat")
                                                    println("Nonce: $nonce")
                                                    println()
                                                    
                                                    val checkCorrectNonce = nonceRegistry[token]
        
                                                    val v = JwtService.getService().verify(jwt)
                                                    println(v)
                                                    // Compruebo que el nonce este firmado correctamente
                                                    if(v.verified && (checkCorrectNonce==nonce)){
                                                        println("Nonce is signed correctly")
                                                        println("Creating credential...")
                                                        val ldSignatureType: LdSignatureType? = null
                                                        val issuerVerificationMethod: String? = null
                                                        val credentialTypes: CredentialStatus.Types? = null
                                                        val selectiveDisclosurePaths: List<String>? = null
                                                        println("Subject: "+issuer)
                                                        println("Issuer: "+DID_BACKEND)
                                                        println()
                                                        val credential = CreateCredential(DID_BACKEND,issuer,template, issuerVerificationMethod, ProofType.LD_PROOF, "assertionMethod", ldSignatureType, Ecosystem.DEFAULT , credentialTypes, DecoyMode.NONE, 0, selectiveDisclosurePaths)
                                                        println(credential)
                                                        call.respond(credential)
                                                    }
                                                    else{
                                                        println(rojo+"[!] ERROR: The sign isn't correct."+reset)
        
                                                    }
        
                                                    // Verificar un did en formato did key
                                                    /* 
        
                                                    val bool = getPublickey_didKey(issuer,publicKey)
                                                    if(publicKey == null || !bool) println("Error getting de public key.")
                                                    else {
                                                        val v = verifyNonce(jwt,"", publicKey) 
                                                        }
        
                                                    */
        
                                                }
                                                else{
                                                    println("Incorrect JWT format.")
                                                }  
                                            }
                                            else
                                            {
                                                println("Incorrect JWT format.")
                                            }
                                        }
                                    }
                                
                            }
                        }
                    }
        
                    embeddedServer(Netty, environment).start(wait = true)                    
                        
                }

            }
            
            fun convertMultiBase58BtcToEd25519PublicKey(multiBase58Btc: String): ByteArray {
                val identify = multiBase58Btc.substringAfter("did:key:")
                val decodedBytes = identify.decodeMultiBase58Btc()
                return decodedBytes.copyOfRange(2, decodedBytes.size)   
            }

            fun obtenerContentsDesdeOctets(octetos: ByteArray): ByteArray {
                val contents = ByteArray(octetos.size + 1)
                contents[0] = 0
                System.arraycopy(octetos, 0, contents, 1, octetos.size)
                return contents
            }


            fun compareByteArrays(array1: ByteArray, array2: ByteArray): Boolean {
                if (array1.size != array2.size) {
                    return false
                }
            
                for (i in array1.indices) {
                    if (array1[i] != array2[i]) {
                        return false
                    }
                }
                return true
            }
            

            fun getPublickey_didKey(did: String, key: String): Boolean{
                println("ISSUER: "+did)

                val pubKeyBytes = convertMultiBase58BtcToEd25519PublicKey(did)
                println("bytes pub key: "+String(pubKeyBytes, Charsets.UTF_8))

                val verifierKey = buildKey(
                    "",
                   "EdDSA_Ed25519",
                    "SUN",
                    key,
                    null
                )
                
                val pubPrim = ASN1Sequence.fromByteArray(verifierKey.getPublicKey().encoded) as ASN1Sequence
                val result2 = (pubPrim.getObjectAt(1) as ASN1BitString).octets
                return compareByteArrays(result2,pubKeyBytes)
            }

            fun obtenerValorPublicKeyBase58(json: String): String? {
                val regex = Regex("\"publicKeyBase58\"\\s*:\\s*\"([^\"]+)\"")       
                val matchResult = regex.find(json)  
                return matchResult?.groupValues?.getOrNull(1)
            }

            fun verifyNonce(token: String, keyId: String, publicKey: String): JwtVerificationResult {
                val jwt = SignedJWT.parse(token)
        
                val verifierKey = buildKey(
                    keyId,
                   "EdDSA_Ed25519",
                    "SUN",
                    publicKey,
                    null
                )

                println(verifierKey)
                val res = jwt.verify(Ed25519Verifier(keyService.toEd25519Jwk(verifierKey)))
                return JwtVerificationResult(res)
            }

            fun generarUriAleatorio(): String {
                val uuid = UUID.randomUUID()
                val uri = "urn:ietf:params:oauth:request_uri:${uuid.toString()}"
                val expirationTime = Instant.now().plusSeconds(60)
                tokenRegistry[uri] = TokenRecord(uri, expirationTime)
                return uri
            }
            
            fun verificarToken(uri: String): Boolean {
                val tokenRecord = tokenRegistry[uri]
                
                if (tokenRecord != null) {
                    val ahora = Instant.now()
                    if (tokenRecord.expirationTime.isAfter(ahora)) {
                        return true 
                    } else {
                        tokenRegistry.remove(uri)
                    }
                }
                
                return false // El token no existe o ha expirado
            }


                

            fun construirPreJWT(uri: String): String {
                val uuid = uri.substringAfterLast(":")
                return JwtService.getService().sign(KEY_ALIAS, JWTClaimsSet.Builder()
                    .claim("sub", uuid)
                    .claim("pre-authorized", "false")
                    .build().toString()
                )
            }

            fun construirJWT(uri: String): String {
                val uuid = uri.substringAfterLast(":")   
                return JwtService.getService().sign(KEY_ALIAS, JWTClaimsSet.Builder()
                    .claim("sub", uuid)
                    .build().toString()
                )
            }


            fun generarAccessToken(usuario: String, refreshToken: String, cNonce: String, idToken: String): String {
                val accessToken = """
                    {
                        "access_token": "$usuario",
                        "refresh_token": "$refreshToken",
                        "c_nonce": "$cNonce",
                        "id_token": "$idToken",
                        "token_type": "Bearer",
                        "expires_in": 60
                    }
                """.trimIndent()
            
                return accessToken
            }

            fun verifyAndExtractUUID(jwt: String): String? {
               
                val verificationResult = JwtService.getService().verify(jwt) 
                if (verificationResult.verified) {
                    val claims = JwtService.getService().parseClaims(jwt) 
                    val sub = claims?.get("sub") 
                    if (sub is String) {
                        return sub 
                    }
                }
                return null 
            }

            fun CreateCredential(issuerDid: String, subjectDid: String, template: String, issuerVerificationMethod: String?, proofType: ProofType, proofPurpose: String, ldSignatureType: LdSignatureType?, ecosystem: Ecosystem , statusType: CredentialStatus.Types?, decoyMode: DecoyMode, numDecoys: Int, selectiveDisclosurePaths: List<String>?): String {
                val signatory = Signatory.getService()
                val selectiveDisclosure = selectiveDisclosurePaths?.let { SDMap.generateSDMap(it, decoyMode, numDecoys) }
        
                val vcStr: String = runCatching {
                    signatory.issue(
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
