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
import id.walt.auditor.PolicyRegistryService
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
import id.walt.common.KlaxonWithConverters
import io.ktor.http.ContentType
import io.ktor.server.http.content.*


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
            val keyStorePath = "$currentWorkingDir/cert/verifier/verifier.p12"

            val DID_BACKEND = "did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK"
            val DOC = """
            {"assertionMethod":["did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK#z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK"],"authentication":["did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK#z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK"],"capabilityDelegation":["did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK#z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK"],"capabilityInvocation":["did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK#z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK"],"@context":"https://www.w3.org/ns/did/v1","id":"did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK","keyAgreement":["did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK#z6LSgGuxWYs6ea3ZBNSrzrPY5LxZYSjKNyTZwHUDkwxhaWAH"],"verificationMethod":[{"controller":"did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK","id":"did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK#z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK","publicKeyBase58":"Eobb9nZ8Ve53rxyMjxYBHV7bf2NMb4f83JcAq91NwTtw","type":"Ed25519VerificationKey2019"},{"controller":"did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK","id":"did:key:z6MktFrdk2oZqBZWyTp4RXW28afbUbeCzwuUjKX6fQyPrggK#z6LSgGuxWYs6ea3ZBNSrzrPY5LxZYSjKNyTZwHUDkwxhaWAH","publicKeyBase58":"5bjnzF4EZ7Kp5z56UCsakkk5hJCCgNHR4JkYGVKAs8PX","type":"X25519KeyAgreementKey2019"}]}
            """

            init {
                
                
                println("Fin del bloque init")
            }
            
            override fun run() {

                runBlocking {
                    var keyStoreFile = File(keyStorePath)
                    val keyStorePassword = ""
                    val privateKeyPassword = ""
                    val keyAlias = "verifier"
                    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
                    keyStore.load(FileInputStream(keyStoreFile), keyStorePassword.toCharArray())
                    println("Inicio del bloque init")
                    VDR.initialize()
                    if(VDR.getValue(DID_BACKEND)==null){
                        VDR.setValue(DID_BACKEND,DOC)  
                    }
                    
                    val environment = applicationEngineEnvironment {
                        log = LoggerFactory.getLogger("ktor.application")
                        connector {
                            port = 5436
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

                                static("/static") {
                                    resources("static")
                                }
        
                                get("/demo") {
                                    val indexHtml = javaClass.classLoader.getResource("static/demoVerifier/index.html")
                                    if (indexHtml != null) {
                                        val content = indexHtml.readText()
                                        call.respondText(content, ContentType.Text.Html)
                                    } else {
                                        call.respond(HttpStatusCode.NotFound)
                                    }
                                }

                                get("/vpToken") {

                                    println("")
                                    println(verde+"[+] Verifier: Obtaion SIOP request."+reset)
                                    println("")

                                    val randomValue = UUID.randomUUID().toString()
                    
                                    // Generate SIOP Request
                                    val client_url = "https://umu-Wallet:8445"
                                    val response_type = "id_token"
                                    val response_mode = "form_post"
                                    val scope: String? = null
                                    val presentationDefinitionUrl: String? = null
                                    val credentialTypes = listOf("demoTemplate")
                                    val state = "$randomValue"
                                    actualState = state


                                    val defaultCredentialTypes = listOf("VerifiableId", "DrivingLicense")

                                    val defaultCredentialSubjectAttributes = listOf(
                                        "$.credentialSubject.gender",
                                        "$.credentialSubject.firstName"
                                    )

                                    val defaultCredentialSubjectValues = listOf(
                                        "male",
                                        "Pedro"
                                    )

                                    val definition = createPresentationDemo(
                                        credentialTypes = defaultCredentialTypes,
                                        credentialSubjectAttributes = defaultCredentialSubjectAttributes,
                                        credentialSubjectValues = defaultCredentialSubjectValues
                                    )

                                    println("Presentation requirements: ${KlaxonWithConverters().toJsonString(definition)}")

                                    val siopRequest = OIDC4VPService.createOIDC4VPRequest(
                                        wallet_url = client_url,
                                        redirect_uri = URI.create("https://umu-demoPoderes:8446"),
                                        nonce = Nonce(randomValue),
                                        response_type = ResponseType.parse(response_type),
                                        response_mode = ResponseMode(response_mode),
                                        scope = scope?.let { Scope(scope) },
                                        presentation_definition = definition,
                                        presentation_definition_uri = presentationDefinitionUrl?.let { URI.create(it) },
                                        state = state?.let { State(it) }
                                    )

                    
                                    if (logs) {

                                        println("")
                                        println(rojo+"[!] Verifier logs: siopRequest - "+siopRequest.toURI().unescapeOpenIdScheme()+reset)
                                        println("")
                                    }

                                    call.respondText(siopRequest.toURI().unescapeOpenIdScheme().toString(), ContentType.Text.Plain)
                    
                                }


                    
                                post("/verifyVP"){


                                    println("")
                                    println(verde+"[+] Verifier: Verify a presentation."+reset)
                                    println("")
                    
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
                                    
                                    println("vp_token: $vpToken\n")
                                    println("presentation_submission: $presentation_submission\n")
                                    println("id_token: $idToken\n")
                                    println("state: $stateResponse\n")

                                    // Verify ID_Token
                                    val verifyId_token = jwtService.verify(idToken)
                                    println("ID_TOKEN Verification: $verifyId_token\n")
                    
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

                                                        
                                    if (logs) {

                                        println("")
                                        println(rojo+"[!] Verifier logs: VerifiablePresentation - "+vp+reset)
                                        println("")
                                    }
                                
                    
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
                    
                    
                                    var policies: Map<String, String?> = emptyMap<String, String?>()
                    
                                    val usedPolicies = policies.ifEmpty { mapOf(PolicyRegistry.defaultPolicyId to null) }
                    
                                    when {
                                        usedPolicies.keys.any { !PolicyRegistry.contains(it) } -> throw NoSuchElementException(
                                            "Unknown verification policy specified: ${
                                                usedPolicies.keys.minus(PolicyRegistry.listPolicies().toSet()).joinToString()
                                            }"
                                        )
                                    }
                    
                                    val policy = PolicyRegistry.getPolicyWithJsonArg("NameAndGenderPolicy", null as JsonObject?)
                                    val verificationResult = Auditor.getService().verify(vc, listOf(policy))
                    
                                    if (logs){
                                        println("\nResults:\n")
                    
                                        verificationResult.policyResults.forEach { (policy, result) ->
                                            println("$policy:\t $result")
                                        }
                                        println("Verified:\t\t ${verificationResult.result}\n")
                                    }
                    
                                    if (verificationResult.result){
                                    
                                        println("Credentials Verified! Sending Access Token to Holder\n")
                                        val dids = DidService.listDids()
                                        var did = DID_BACKEND
                    
                                        val url = call.request.headers["url"]
                                        val method = call.request.headers["method"]
                                        val requester = call.request.headers["requester"]
                    
                                        val expiration_time: Long = try {
                                            System.getenv("expiration_time")?.toLong() ?: 60L
                                        } catch (e: NumberFormatException) {
                                            60L
                                        }
                    
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
            

            fun createPresentationDemo(
                credentialTypes: List<String>, // Nuevo parámetro para los tipos de credencial
                credentialSubjectAttributes: List<String>,
                credentialSubjectValues: List<String>
            ): PresentationDefinition {
                if (credentialSubjectAttributes.size != credentialSubjectValues.size) {
                    throw IllegalArgumentException("Las listas de atributos y valores deben tener el mismo tamaño.")
                }

                val inputDescriptorFields = mutableListOf<InputDescriptorField>()

                // Crear InputDescriptorFields para los tipos de credencial
                credentialTypes.forEachIndexed { index, type ->
                    inputDescriptorFields.add(
                        InputDescriptorField(
                            path = listOf("$.type"),
                            id = "typeField$index", // Asegurar un ID único para cada campo
                            filter = mapOf(
                                "type" to "array",
                                "contains" to mapOf("const" to type)
                            )
                        )
                    )
                }

                // Añadir InputDescriptorFields dinámicamente para cada par atributo-valor
                credentialSubjectAttributes.forEachIndexed { index, attribute ->
                    inputDescriptorFields.add(
                        InputDescriptorField(
                            path = listOf(attribute),
                            id = "credentialSubjectField$index", // Asegurar un ID único para cada campo
                            filter = mapOf("const" to credentialSubjectValues[index])
                        )
                    )
                }

                return PresentationDefinition(
                    id = "2",
                    input_descriptors = listOf(
                        InputDescriptor(
                            id = "1",
                            constraints = InputDescriptorConstraints(
                                fields = inputDescriptorFields
                            )
                        )
                    )
                )
            }

            

            fun createPresentationDemo1(): PresentationDefinition {
                return PresentationDefinition(
                    id = "2",
                    input_descriptors = listOf(
                        InputDescriptor(
                            id = "1",
                            constraints = InputDescriptorConstraints(
                                fields = listOf(
                                    InputDescriptorField(
                                        path = listOf("$.type"),
                                        id = "typeField",
                                        filter = JsonObject(mapOf(
                                            "type" to "array",
                                            "contains" to mapOf("const" to "VerifiableId")
                                        ))
                                    ),
                                    InputDescriptorField(
                                        path = listOf("$.credentialSubject.gender"),
                                        id = "genderField",
                                        filter = JsonObject(mapOf("const" to "male"))
                                    )
                                )
                            )
                        )
                    ),
                    name = "Gender-Specific Presentation Definition",
                    purpose = "To verify a Verifiable ID credential with gender specified as male."
                )
            }


            
            

            
        }
