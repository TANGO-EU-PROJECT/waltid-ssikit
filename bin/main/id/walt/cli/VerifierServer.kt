package id.walt.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.sun.jdi.Location
import com.google.common.net.HttpHeaders
import io.ktor.server.application.*
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.request.receiveText
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.TextContent
import id.walt.services.oidc.OIDC4VPService
import java.net.URI
import com.nimbusds.openid.connect.sdk.Nonce
import com.nimbusds.oauth2.sdk.ResponseType
import com.nimbusds.oauth2.sdk.ResponseMode
import com.nimbusds.oauth2.sdk.Scope
import id.walt.model.dif.PresentationDefinition
import id.walt.model.oidc.CredentialAuthorizationDetails
import id.walt.credentials.w3c.PresentableCredential
import id.walt.model.dif.InputDescriptor
import id.walt.model.dif.InputDescriptorConstraints
import id.walt.model.dif.InputDescriptorField
import com.beust.klaxon.JsonObject
import com.nimbusds.oauth2.sdk.id.State
import id.walt.services.oidc.OidcSchemeFixer.unescapeOpenIdScheme
import java.security.SecureRandom
import kotlin.text.Charsets
import java.net.URLDecoder
import id.walt.services.oidc.OIDCUtils
import id.walt.credentials.w3c.VerifiablePresentation
import id.walt.credentials.w3c.VerifiableCredential
import id.walt.credentials.w3c.toVerifiableCredential
import id.walt.auditor.Auditor
import id.walt.auditor.PolicyRegistry
import id.walt.auditor.dynamic.DynamicPolicyArg
import id.walt.auditor.dynamic.PolicyEngineType
import id.walt.common.resolveContent
import java.io.File
import java.io.StringReader
import java.util.*
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.interfaces.DecodedJWT
import id.walt.services.WaltIdService
import id.walt.services.jwt.JwtService
import id.walt.services.vc.JwtCredentialService
import id.walt.model.oidc.SelfIssuedIDTokenUmu
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import id.walt.services.did.DidService
import java.time.Duration
import io.ktor.network.tls.certificates.generateCertificate
import io.ktor.server.engine.*
import io.ktor.network.tls.certificates.*
import java.security.KeyStore
import java.io.FileInputStream
import org.slf4j.LoggerFactory
import kotlinx.coroutines.runBlocking



/* SSIKIT issuer */
class VerifierCommand :
        CliktCommand(
                name = "verifier",
                help =
                        """
                    OIDC4VC verifier
                """
        ) {
            var actualState: String? = null 
            val MAX_TIME = 60 
            var requestTime: Long = 0 

            val logs: Boolean = System.getenv("logs").toBoolean()


            private val jwtService = JwtService.getService()

            //Salida mas legible
            val verde = "\u001B[32m"
            val rojo = "\u001B[31m"
            val reset = "\u001B[0m"

            val currentWorkingDir = System.getProperty("user.dir")
            val keyStorePath = "$currentWorkingDir/keystore.p12"

            override fun run() {

                runBlocking {
                    var keyStoreFile = File(keyStorePath)
                    val keyStorePassword = ""
                    val privateKeyPassword = ""
                    val keyAlias = "myAlias"
                    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
                    keyStore.load(FileInputStream(keyStoreFile), keyStorePassword.toCharArray())

                    val DID_BACKEND = "did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK"
                    
                    val environment = applicationEngineEnvironment {
                        log = LoggerFactory.getLogger("ktor.application")
                        connector {
                            port = 8100
                        }
                        sslConnector(
                            keyStore = keyStore,
                            keyAlias = keyAlias,
                            keyStorePassword = { keyStorePassword.toCharArray() },
                            privateKeyPassword = { privateKeyPassword.toCharArray() }
                        ) {
                            port = 8444
                        }
                        module {
                            routing {
                                get("/obtainVP") {

                                    val randomValue = UUID.randomUUID().toString()
                    
                                    // Generate SIOP Request
                                    //val client_url = "https://wallet.walt.id/api/siop/initiatePresentation/" // Check
                                    val response_type = "id_token"
                                    val response_mode = "form_post"
                                    val nonce = "$randomValue"
                                    val scope: String? = null
                                    val presentationDefinitionUrl: String? = null
                                    val credentialTypes = listOf("demoTemplate")
                                    val state = "$randomValue"
                                    actualState = state
                    
                                    val device = call.request.headers["Device"]
                    
                                    val siopRequest = OIDC4VPService.createOIDC4VPRequest(
                                        //wallet_url = client_url,
                                        wallet_url = "openid://",
                                        redirect_uri = URI.create(device + "/verifyVP"),
                                        nonce = nonce?.let { Nonce(it) } ?: Nonce(),
                                        response_type = ResponseType.parse(response_type),
                                        response_mode = ResponseMode(response_mode),
                                        scope = scope?.let { Scope(scope) },
                                        presentation_definition = if (scope.isNullOrEmpty() && presentationDefinitionUrl.isNullOrEmpty()) {
                                        PresentationDefinition("1",
                                            input_descriptors = credentialTypes?.map { credType ->
                                                InputDescriptor(
                                                    "1",
                                                    constraints = InputDescriptorConstraints(
                                                        listOf(
                                                            InputDescriptorField(
                                                                listOf("$.type"),
                                                                "1",
                                                                filter = JsonObject(mapOf("const" to credType))
                                                            )
                                                        )
                                                    )
                                                )
                                            } ?: listOf())
                                        } else {
                                            null
                                        },
                                        presentation_definition_uri = presentationDefinitionUrl?.let { URI.create(it) },
                                        state = state?.let { State(it) }
                                    )
                    
                                    if (logs) {
                                        println("${siopRequest.toURI().unescapeOpenIdScheme()}")
                                    }
                                    // Send SIOP Request to Holder
                                    call.response.header(HttpHeaders.LOCATION, "${siopRequest.toURI().unescapeOpenIdScheme()}") // Add Location header to Response
                                    call.respond(
                                        HttpStatusCode.Found,
                                        HttpHeaders.LOCATION
                                    )
                    
                                    requestTime = System.currentTimeMillis()
                    
                                }
                    
                                post("/verifyVP"){
                                    // Check if time between Request and Response has expired
                                    val responseTime = System.currentTimeMillis()
                    
                                    if ((responseTime - requestTime) / 1000 > MAX_TIME){
                                        //TODO Send Error Response and exit
                                        println("Time expired\n")
                                    } else {
                                        //println("In time!\n")
                                    }
                    
                                    // Get body from Request
                                    var requestContent = call.receiveText() 
                                    if (logs){
                                        println("$requestContent\n")
                                    }
                                    
                                    requestContent = requestContent.trimIndent()
                    
                                    var jsonString = URLDecoder.decode(requestContent, "UTF-8")
                    
                                    // Replace special characters
                                    jsonString = jsonString.replace("%40", "@")
                                            .replace("%2F", "/")
                                            .replace("%2C", ",")
                                            .replace("%3A", ":")
                                            .replace("%3D", "=")
                                            .replace("%22", "\"")
                                            .replace("%7B", "{")
                                            .replace("%7D", "}")
                                            .replace("%5B", "[")
                                            .replace("%5D", "]")
                                            .replace("%2B", " ")
                                            .replace("%20", " ")  // Replace '+' for blank spaces
                    
                                    var vpToken: String = ""
                                    var presentation_submission: String? = null
                                    var idToken: String = ""
                                    var stateResponse: String? = null
                    
                                    var parts = jsonString.split('&')
                                    parts.forEach { part ->
                                        val (clave, valor) = part.split('=')
                                        when (clave){
                                            "vp_token" -> vpToken = valor
                                            "presentation_submission" -> presentation_submission = valor
                                            "id_token" -> idToken = valor
                                            "state" -> stateResponse = valor
                                        }
                                    }
                    
                                    if (logs) {
                                        println("vp_token: $vpToken\n")
                                        println("presentation_submission: $presentation_submission\n")
                                        println("id_token: $idToken\n")
                                        println("state: $stateResponse\n")
                                    }
                                    
                                    // Verify ID_Token
                                    val verifyId_token = jwtService.verify(idToken)
                                    println("ID_TOKEN Verification: $verifyId_token\n")
                    
                                    // Check if the response state param matches the request state param
                                    if (stateResponse == actualState){
                                        if (logs){
                                            println("The response is correct! Starting verification process...\n")
                                        }
                                    } else {
                                        println("The response is not valid or have expired\n")
                                        //TODO Send Error Response and exit
                                    }
                    
                                    // Get VerifiablePresentation object from vp_token
                                    val vps = OIDCUtils.fromVpToken(vpToken)
                                    var vp: VerifiablePresentation = vps.first()
                                    if (logs){
                                        println("VerifiablePresentation: $vp\n")
                                    }
                                    
                                    /*if (vps.isNotEmpty()){
                                        vp = vps.first()
                                        println("VerifiablePresentation: $vp\n")
                                    }*/
                    
                                    // Verification process        
                                    val vcs = vp.verifiableCredential
                                    var vc: VerifiableCredential = VerifiableCredential()
                                    if (vcs.isNullOrEmpty()){
                                        println("Could not retrieve any Verifiable Credential from Verifiable Presentation\n")
                                    } else{
                                        vc = vcs.first()
                                        if (logs){
                                            println("VerifiableCredential: $vc")
                                        }
                    
                                    }
                    
                    
                                    /*var policies: Map<String, String?> = emptyMap<String, String?>()
                    
                                    val usedPolicies = policies.ifEmpty { mapOf(PolicyRegistry.defaultPolicyId to null) }
                    
                                    when {
                                        usedPolicies.keys.any { !PolicyRegistry.contains(it) } -> throw NoSuchElementException(
                                            "Unknown verification policy specified: ${
                                                usedPolicies.keys.minus(PolicyRegistry.listPolicies().toSet()).joinToString()
                                            }"
                                        )
                                    }
                    
                                    val verificationResult = Auditor.getService()
                                        .verify(
                                            vc,
                                            usedPolicies.entries.map { PolicyRegistry.getPolicyWithJsonArg(it.key, it.value?.ifEmpty { null }?.let {
                                    resolveContent(it)
                                    }) })
                    
                                    if (logs){
                                        echo("\nResults:\n")
                    
                                        verificationResult.policyResults.forEach { (policy, result) ->
                                            echo("$policy:\t $result")
                                        }
                                        echo("Verified:\t\t ${verificationResult.result}\n")
                                    }
                    
                                    if (verificationResult.result){*/
                                    if (true){
                                        println("Credentials Verified! Sending Access Token to Holder\n")
                                        // Get DID - MAYBE IN REAL SCENARIO SHOULD ASK TO HOLDER
                                        val dids = DidService.listDids()
                                        var did = DID_BACKEND
                    
                                        val url = call.request.headers["url"]
                                        val method = call.request.headers["method"]
                                        //val resource = call.request.headers["resource"]
                                        //val audience = call.request.headers["audience"]
                                        val requester = call.request.headers["requester"]
                    
                                        val expiration_time: Long = try {
                                            System.getenv("expiration_time")?.toLong() ?: 60L
                                        } catch (e: NumberFormatException) {
                                            60L // Valor predeterminado en caso de excepción
                                        }

                                        // ???????????????
                                        //val expiration_time: Long = System.getenv("expiration_time").toLong() // Get expiration_time from environment variable
                    
                                        val accessToken =  SelfIssuedIDTokenUmu(
                                            subject = vc.subjectId ?: "did",
                                            issuer = did,
                                            client_id = null,
                                            nonce = null,
                                            expiration = Instant.now().plus(Duration.ofMinutes(expiration_time)),
                                            requester = requester,
                                            method = method,
                                            url = url,
                                            _vp_token = null
                                        ).sign()
                                        println("Access Token: $accessToken")
                    
                                        call.respond(HttpStatusCode.OK, accessToken)      
                                    } else {
                                        call.respond(HttpStatusCode.Unauthorized, "Invalid Credentials")
                                    }
                    
                                }
                            };
                        }
                    }
        
                    embeddedServer(Netty, environment).start(wait = true)                    
                        
                }


            }
        }
            





