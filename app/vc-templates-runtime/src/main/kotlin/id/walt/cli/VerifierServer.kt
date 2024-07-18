package id.walt.cli

import com.github.ajalt.clikt.core.CliktCommand
import io.ktor.server.application.*
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.request.receiveText
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.http.HttpStatusCode
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
import com.google.gson.Gson
import id.walt.services.jwt.JwtService
import id.walt.model.oidc.SelfIssuedIDTokenUmu
import java.time.Instant
import id.walt.services.did.DidService
import java.time.Duration
import io.ktor.server.engine.*
import java.security.KeyStore
import java.io.FileInputStream
import org.slf4j.LoggerFactory
import kotlinx.coroutines.runBlocking
import id.walt.services.did.DidService.keyService
import io.ktor.http.ContentType
import io.ktor.server.http.content.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject as jsonObject2
import java.util.Base64
import id.walt.services.ecosystems.fabric.VDR
import com.google.gson.JsonObject
import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.KeyIdUmu
import id.walt.crypto.KeyUmu
import id.walt.model.DidMethod
import id.walt.services.keyUmu.KeyServiceUmu
import id.walt.services.storeUmu.KeyStoreServiceUmu
import inf.um.multisign.MS
import inf.um.multisign.MSauxArg
import inf.um.psmultisign.PSauxArg
import inf.um.psmultisign.PSms
import inf.um.psmultisign.PSprivateKey
import inf.um.psmultisign.PSverfKey
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
    val MAX_TIME = 60
    var requestTime: Long = 0


    //Salida mas legible
    val verde = "\u001B[32m"
    val rojo = "\u001B[31m"
    val reset = "\u001B[0m"


    val currentWorkingDir = System.getProperty("user.dir")
    val keyStorePath = "$currentWorkingDir/cert/verifier/verifier.p12"

    // DID del wallet
    lateinit var DID_BACKEND: String
    // ID de la clave asociada al DID del WALLET
    lateinit var KEY_ALIAS: String
    private val keyStoreUmu = KeyStoreServiceUmu.getService()
    private val keyServiceUmu = KeyServiceUmu.getService()

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

                        /*

                            Interfaz web del verifier

                        */

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
                                val indexHtml = javaClass.classLoader.getResource("static/firmaValidaVerifier/index.html")
                                if (indexHtml != null) {
                                    val content = indexHtml.readText()
                                    call.respondText(content, ContentType.Text.Html)
                                } else {
                                    call.respond(HttpStatusCode.NotFound)
                                }
                            }
                            else {
                                val indexHtml = javaClass.classLoader.getResource("static/firmaInvalidaVerifier/index.html")
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
                                redirect_uri = URI.create("https://umu-demoPoderes:8446"),
                                nonce = Nonce(randomValue),
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


                            log.debug { "verifyVP -> [!] Verifier logs: vpToken - ${vpToken}" }.toString()
                            log.debug { "verifyVP -> [!] Verifier logs: presentation_submission - ${presentation_submission}" }.toString()
                            log.debug { "verifyVP -> [!] Verifier logs: id_token - ${idToken}" }.toString()
                            log.debug { "verifyVP -> [!] Verifier logs: state - ${stateResponse}" }.toString()



                            // Verify ID_Token
                            val verifyId_token = verifyJWT(idToken)

                            if (stateResponse == actualState){

                            } else {
                                println("The response is not valid or have expired\n")
                                //TODO Send Error Response and exit
                            }

                            // Get VerifiablePresentation object from vp_token
                            val vps = OIDCUtils.fromVpToken(vpToken)
                            var vp: VerifiablePresentation = vps.first()


                            log.debug { "verifyVP -> [!] Verifier logs: VerifiablePresentation - ${vp}" }.toString()


                            // EL siguiente código obtiene la primera credencial del conjunto de VP



                            // Verification process
                            val vcs = vp.verifiableCredential
                            var vc: VerifiableCredential = VerifiableCredential()
                            if (vcs.isNullOrEmpty()){
                                println("Could not retrieve any Verifiable Credential from Verifiable Presentation\n")
                            } else{
                                vc = vcs.first()
                                log.debug { "verifyVP -> [!] Verifier logs: VerifiableCredential - ${vc}" }.toString()

                            }




                            //val vc = vp

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



        KEY_ALIAS = kid_key.id
        println("verifier did: "+DID_BACKEND)




    }





}
