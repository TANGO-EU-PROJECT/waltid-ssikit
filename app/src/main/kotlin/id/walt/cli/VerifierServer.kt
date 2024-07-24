package id.walt.cli

import com.github.ajalt.clikt.core.CliktCommand
import io.ktor.server.application.*
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.response.*
import io.ktor.server.routing.*
import id.walt.services.oidc.OIDC4VPService
import java.net.URI
import com.nimbusds.openid.connect.sdk.Nonce
import com.nimbusds.oauth2.sdk.ResponseType
import com.nimbusds.oauth2.sdk.ResponseMode
import com.nimbusds.oauth2.sdk.Scope
import id.walt.model.dif.PresentationDefinition
import id.walt.model.dif.InputDescriptor
import id.walt.model.dif.InputDescriptorConstraints
import id.walt.model.dif.InputDescriptorField
import com.beust.klaxon.JsonObject as JsonObjectOPA
import com.nimbusds.oauth2.sdk.id.State
import id.walt.services.oidc.OidcSchemeFixer.unescapeOpenIdScheme
import java.net.URLDecoder
import id.walt.services.oidc.OIDCUtils
import id.walt.credentials.w3c.VerifiablePresentation
import id.walt.credentials.w3c.VerifiableCredential
import id.walt.auditor.Auditor
import id.walt.auditor.PolicyRegistry
import java.io.File
import java.util.*
import id.walt.services.jwt.JwtService
import id.walt.model.oidc.SelfIssuedIDTokenUmu
import java.time.Instant
import id.walt.services.did.DidService
import java.time.Duration
import io.ktor.server.engine.*
import java.security.KeyStore
import java.io.FileInputStream
import kotlinx.coroutines.runBlocking
import id.walt.services.did.DidService.keyService
import io.ktor.server.http.content.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject as jsonObject2
import java.util.Base64
import id.walt.credentials.w3c.toVerifiableCredential
import id.walt.crypto.KeyAlgorithm
import id.walt.model.DidMethod
import id.walt.services.OIDC_UMU.generarValorAleatorio
import id.walt.services.OIDC_UMU.isProofValid
import id.walt.services.OIDC_UMU.wallet.AuthorizationRequest
import id.walt.services.OIDC_UMU.wallet.CrendentialRequest
import id.walt.services.keyUmu.KeyServiceUmu
import id.walt.services.storeUmu.KeyStoreServiceUmu
import id.walt.services.vc.JsonLdCredentialService
import io.ktor.http.*
import io.ktor.server.plugins.cors.*
import io.ktor.server.request.*
import mu.KotlinLogging


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

    //Salida mas legible
    val verde = "\u001B[32m"
    val rojo = "\u001B[31m"
    val reset = "\u001B[0m"


    val currentWorkingDir = System.getProperty("user.dir")
    val keyStorePath = "$currentWorkingDir/cert/verifier/verifier.p12"
    private val credentialService = JsonLdCredentialService.getService()

    // DID del wallet
    lateinit var DID_BACKEND: String
    // ID de la clave asociada al DID del WALLET
    lateinit var KEY_ALIAS: String
    private val keyStoreUmu = KeyStoreServiceUmu.getService()
    private val keyServiceUmu = KeyServiceUmu.getService()
    private val VERIFIER_PORT = System.getenv("VERIFIER_PORT").toInt()
    val stateMap: MutableMap<String, Instant> = mutableMapOf()
    val local = System.getenv("LOCAL").toBoolean()
    override fun run() {

        initialization()

        runBlocking {
            var keyStoreFile = File(keyStorePath)
            val keyStorePassword = ""
            val privateKeyPassword = ""
            val keyAlias = "verifier"
            val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
            keyStore.load(FileInputStream(keyStoreFile), keyStorePassword.toCharArray())


            val environment = applicationEngineEnvironment {
                val log = KotlinLogging.logger {}
                connector {
                    port = VERIFIER_PORT
                }
                sslConnector(
                    keyStore = keyStore,
                    keyAlias = keyAlias,
                    keyStorePassword = { keyStorePassword.toCharArray() },
                    privateKeyPassword = { privateKeyPassword.toCharArray() }
                ) {
                    port = VERIFIER_PORT+100
                }
                module {
                    install(CORS) {
                        allowCredentials = true
                        allowNonSimpleContentTypes = true
                        allowSameOrigin = true
                        anyHost()  // Permite solicitudes CORS desde cualquier origen
                        allowHeader(HttpHeaders.ContentType)
                    }

                    routing {

                        /*

                            Interfaz web del verifier

                        */

                        static("/static") {
                            resources("static")
                        }

                        get("/") {
                            val indexHtml = javaClass.classLoader.getResource("static/verifier/main/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }

                        // Redirige a una pestaña u otra en función de la validez del JWT

                        get("/verify") {

                            println("\n$verde[+] Verifier: Verify a JWT.$reset\n")



                            val jwt = call.request.queryParameters["TokenJWT"]
                            log.debug { "verify -> [!] Verifier logs: jwt - ${jwt}" }.toString()
                            var bool = false
                            if (jwt!=null) {
                                bool = isJwtValid(jwt)
                                log.debug { "verify -> [!] Verifier logs: isValid - ${bool}" }.toString()

                            }

                            if(bool){
                                val indexHtml = javaClass.classLoader.getResource("static/verifier/firmaValidaVerifier/index.html")
                                if (indexHtml != null) {
                                    val content = indexHtml.readText()
                                    call.respondText(content, ContentType.Text.Html)
                                } else {
                                    call.respond(HttpStatusCode.NotFound)
                                }
                            }
                            else {
                                val indexHtml = javaClass.classLoader.getResource("static/verifier/firmaInvalidaVerifier/index.html")
                                if (indexHtml != null) {
                                    val content = indexHtml.readText()
                                    call.respondText(content, ContentType.Text.Html)
                                } else {
                                    call.respond(HttpStatusCode.NotFound)
                                }
                            }

                        }

                        /*

                            Emisión de un vp token con la política que debe cumplirse para superar
                            el proceso de autorización.

                        */

                        get("/vpToken") {



                            println("\n$verde[+] Verifier: Obtaion SIOP request.$reset\n")


                            // Generate SIOP Request
                            val client_url = "http://example.com"
                            val response_type = "id_token"
                            val response_mode = "form_post"
                            val scope: String? = null
                            val presentationDefinitionUrl: String? = null
                            val state = generarValorAleatorio()
                            createState(state, Duration.ofMinutes(1))
                            actualState = state


                            val defaultCredentialTypes = listOf("PermanentResidentCard")

                            val defaultCredentialSubjectAttributes = listOf(
                                "$.credentialSubject.gender",
                                "$.credentialSubject.givenName"
                            )

                            val defaultCredentialSubjectValues = listOf(
                                "Male",
                                "Pedro"
                            )

                            val definition = createPresentationDemo(
                                credentialTypes = defaultCredentialTypes,
                                credentialSubjectAttributes = defaultCredentialSubjectAttributes,
                                credentialSubjectValues = defaultCredentialSubjectValues
                            )


                            // Generación del SIOP request
                            val siopRequest = OIDC4VPService.createOIDC4VPRequest(
                                wallet_url = client_url,
                                redirect_uri = URI.create("http://wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu/verifier/verifyVP"),
                                nonce = Nonce(state),
                                response_type = ResponseType.parse(response_type),
                                response_mode = ResponseMode(response_mode),
                                scope = scope?.let { Scope(scope) },
                                presentation_definition = definition,
                                presentation_definition_uri = presentationDefinitionUrl?.let { URI.create(it) },
                                state = state?.let { State(it) }
                            )

                            log.debug { "vpToken -> [!] Verifier logs: siopRequest - ${siopRequest.toURI().unescapeOpenIdScheme()}" }.toString()

                            call.respondText(siopRequest.toURI().unescapeOpenIdScheme().toString(), ContentType.Text.Plain)

                        }

                        /*

                            Este endpoint recibe un vptoken que contiene la presentación generada por el wallet. Tras parsear
                            este token y obtener toda la información comienza el proceso de verificación.

                            Primero de todo obtiene la política usada en esta demo "NameAndGenderPolicy" y comprueba que la presentación
                            cumple con esta política

                        */

                        post("/verifyVP"){

                            println("\n$verde[+] Verifier: Verify a presentation.$reset\n")

                            // Get body from Request
                            var requestContent = call.receiveText()

                            log.debug { "verifyVP -> [!] Verifier logs: requestContent - ${requestContent}" }.toString()

                            val decodedString = URLDecoder.decode(requestContent.trimIndent(), "UTF-8")

                            // Extraer cada parámetro en un mapa para un acceso fácil
                            val params = decodedString.split('&').map { it.split('=') }.associate { it[0] to (it.getOrNull(1) ?: "") }

                            // Extraer valores específicos usando el mapa
                            val vpToken = params["vp_token"]
                            val presentationSubmission = params["presentation_submission"]
                            val idToken = params["id_token"]
                            val stateResponse = params["state"]

                            if (vpToken.isNullOrBlank() || presentationSubmission.isNullOrBlank() || idToken.isNullOrBlank() || stateResponse.isNullOrBlank()) throw IllegalArgumentException ("Error in the request content")

                            log.debug { "verifyVP -> [!] Verifier logs: vpToken - ${vpToken}" }.toString()
                            log.debug { "verifyVP -> [!] Verifier logs: presentation_submission - ${presentationSubmission}" }.toString()
                            log.debug { "verifyVP -> [!] Verifier logs: id_token - ${idToken}" }.toString()
                            log.debug { "verifyVP -> [!] Verifier logs: state - ${stateResponse}" }.toString()


                            if (! isStateValid(stateResponse) || ! isProofValid(idToken,stateResponse,"nonce")) call.respond(HttpStatusCode.Unauthorized, "Invalid Credentials")

                            // Get VerifiablePresentation object from vp_token
                            val vps = OIDCUtils.fromVpToken(vpToken)
                            var vp: VerifiablePresentation = vps.first()


                            log.debug { "verifyVP -> [!] Verifier logs: VerifiablePresentation - ${vp}" }.toString()

                            // Verification process
                            val vcs = vp.verifiableCredential

                            if (vcs.isNullOrEmpty()){
                                println("Could not retrieve any Verifiable Credential from Verifiable Presentation\n")
                                call.respond(HttpStatusCode.Unauthorized, "Invalid Credentials")
                            }

                            val vc = vcs!!.first()
                            log.debug { "verifyVP -> [!] Verifier logs: VerifiableCredential - ${vc}" }.toString()


                            var policies: Map<String, String?> = emptyMap<String, String?>()

                            val usedPolicies = policies.ifEmpty { mapOf(PolicyRegistry.defaultPolicyId to null) }

                            when {
                                usedPolicies.keys.any { !PolicyRegistry.contains(it) } -> throw NoSuchElementException(
                                    "Unknown verification policy specified: ${
                                        usedPolicies.keys.minus(PolicyRegistry.listPolicies().toSet()).joinToString()
                                    }"
                                )
                            }

                            val policy = PolicyRegistry.getPolicyWithJsonArg("NameAndGenderPolicy", null as JsonObjectOPA?)

                            val verificationResult = Auditor.getService().verify(vc, listOf(policy))

                            val verifySign = credentialService.verify(vc.toString())

                            if (verificationResult.result && verifySign.verified){

                                val url = call.request.headers["url"]
                                val method = call.request.headers["method"]
                                val requester = call.request.headers["requester"]

                                val expiration_time: Long = try {
                                    System.getenv("expiration_time")?.toLong() ?: 60L
                                } catch (e: NumberFormatException) {
                                    60L
                                }

                                val accessToken =  SelfIssuedIDTokenUmu(
                                    issuer = DID_BACKEND,
                                    subject = vc.subjectId ?: "did",
                                    client_id = null,
                                    nonce = null,
                                    expiration = Instant.now().plus(Duration.ofMinutes(expiration_time)),
                                    requester = requester,
                                    method = method,
                                    url = "http://wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu/verifier/verify",
                                    _vp_token = null,
                                    keyId = KEY_ALIAS
                                ).sign()


                                call.respond(HttpStatusCode.OK, accessToken)
                            } else {
                                call.respond(HttpStatusCode.Unauthorized, "Invalid Credentials")
                            }

                        }

                        post("/verifyCred"){

                            println("\n$verde[+] Verifier: Verify a presentation.$reset\n")

                            val parameters = call.receiveParameters()
                            val cred = parameters["cred"]

                            if (cred==null)  throw IllegalArgumentException("The credential isn't valid.")


                            var vc: VerifiableCredential = cred.toVerifiableCredential()

                            var policies: Map<String, String?> = emptyMap<String, String?>()

                            val usedPolicies = policies.ifEmpty { mapOf(PolicyRegistry.defaultPolicyId to null) }

                            when {
                                usedPolicies.keys.any { !PolicyRegistry.contains(it) } -> throw NoSuchElementException(
                                    "Unknown verification policy specified: ${
                                        usedPolicies.keys.minus(PolicyRegistry.listPolicies().toSet()).joinToString()
                                    }"
                                )
                            }

                            val policy = PolicyRegistry.getPolicyWithJsonArg("NameAndGenderPolicy", null as JsonObjectOPA?)

                            val verificationResult = Auditor.getService().verify(vc, listOf(policy))

                            if (verificationResult.result){


                                val url = call.request.headers["url"]
                                val method = call.request.headers["method"]
                                val requester = call.request.headers["requester"]

                                val expiration_time: Long = try {
                                    System.getenv("expiration_time")?.toLong() ?: 60L
                                } catch (e: NumberFormatException) {
                                    60L
                                }

                                val accessToken =  SelfIssuedIDTokenUmu(
                                    issuer = DID_BACKEND,
                                    subject = vc.subjectId ?: "did",
                                    client_id = null,
                                    nonce = null,
                                    expiration = Instant.now().plus(Duration.ofMinutes(expiration_time)),
                                    requester = requester,
                                    method = method,
                                    url = url,
                                    _vp_token = null,
                                    keyId = KEY_ALIAS
                                ).sign()


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
                                filter = JsonObjectOPA(mapOf(
                                    "type" to "array",
                                    "contains" to mapOf("const" to "VerifiableId")
                                ))
                            ),
                            InputDescriptorField(
                                path = listOf("$.credentialSubject.gender"),
                                id = "genderField",
                                filter = JsonObjectOPA(mapOf("const" to "male"))
                            )
                        )
                    )
                )
            ),
            name = "Gender-Specific Presentation Definition",
            purpose = "To verify a Verifiable ID credential with gender specified as male."
        )
    }


    // Obtiene un determinado valor (v) dentro de un JWT
    fun getValueFromJWT(jwt: String, v: String): String {
        val parts = jwt.split(".")
        val payload = parts[1]
        val decodedPayload = String(Base64.getDecoder().decode(payload))
        val jsonElement = Json.parseToJsonElement(decodedPayload)
        val content = jsonElement.jsonObject2[v]?.toString()?.removeSurrounding("\"") ?: throw IllegalArgumentException("Error processing the JWT.")
        return content
    }


    fun verifyJWT(jwt: String): Boolean
    {
        val iss =  getValueFromJWT(jwt, "iss")
        DidService.importDidAndKeys(iss)
        val result = JwtService.getService().verify(jwt).verified
        return result
    }


    fun isJwtValid(jwt: String): Boolean {
        val parts = jwt.split(".")
        if (parts.size != 3) return false

        val payload = parts[1]
        val decodedPayload = String(Base64.getDecoder().decode(payload))

        val jsonObject2 = Json.parseToJsonElement(decodedPayload)
        if (!jsonObject2.jsonObject2.containsKey("iss") ||
            !jsonObject2.jsonObject2.containsKey("exp") ||
            !jsonObject2.jsonObject2.containsKey("iat") ||
            !jsonObject2.jsonObject2.containsKey("sub")) return false

        val exp = jsonObject2.jsonObject2["exp"]?.toString()?.toLongOrNull() ?: return false
        val iat = jsonObject2.jsonObject2["iat"]?.toString()?.toLongOrNull() ?: return false

        val currentTime = Instant.now().epochSecond
        if (currentTime > exp) return false // Verifica si el token ha expirado.
        if ((currentTime - iat) > 60) return false // Verifica que no han pasado más de 1 minuto desde su emisión.

        return verifyJWT(jwt)
    }

    fun createState(nonce: String, expirationDuration: Duration) {
        val expirationTime = Instant.now().plus(expirationDuration)
        stateMap[nonce] = expirationTime
    }

    fun isStateValid(nonce: String): Boolean {
        val currentTime = Instant.now()
        val expirationTime = stateMap[nonce]

        return expirationTime != null && expirationTime.isAfter(currentTime)
    }


    fun initialization(){
        val kid_key = keyService.generate(KeyAlgorithm.EdDSA_Ed25519)

        if (local){
            DID_BACKEND = DidService.create(DidMethod.key,kid_key.id)
            KEY_ALIAS = DID_BACKEND
        }
        else
        {
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

            keyService.addAlias(kid_key,kid_key.id)
            DID_BACKEND = DidService.createUmu(kid_fabric.id,DidMethod.fabric,null,kid_key.id)
            KEY_ALIAS = kid_key.id
        }



        println("verifier did: "+DID_BACKEND)

    }
}
