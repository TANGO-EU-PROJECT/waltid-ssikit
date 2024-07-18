package id.walt.services.OIDC_UMU.issuer

import id.walt.cli.IssuerCommand
import id.walt.services.OIDC_UMU.sha256
import id.walt.services.jwt.WaltIdJwtService
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import mu.KotlinLogging
import java.util.*

// Salida mas legible
val verde = "\u001B[32m"
val rojo = "\u001B[31m"
val reset = "\u001B[0m"


class ClientIdOauth{

    val log = KotlinLogging.logger {}
    val jwtService = WaltIdJwtService()
    suspend fun register(call: ApplicationCall, clientID:  MutableMap<String, IssuerCommand.clientIdValues>, clientCredentials: MutableMap<String,String>, userDetails: MutableMap<String,IssuerCommand.userData>) {
        println("\n$verde[+] Issuer: Register a user.$reset\n")

        val parameters = call.receiveParameters()
        val user = parameters["user"]
        val pass = parameters["pass"]
        val givenName = parameters["givenName"] ?: ""
        val familyName = parameters["familyName"] ?: ""
        val gender = parameters["gender"] ?: ""
        val birthDate = parameters["birthDate"] ?: ""
        val birthCountry = parameters["birthCountry"] ?: ""

        log.debug { "registerBackend -> [!] Issuer logs: username - $user password - $pass" }.toString()

        if (clientCredentials.containsKey(user)) {
            call.respondText("This username is already registered.")
        } else {
            if (user != null && pass != null) {
                clientCredentials[user] = pass.sha256()
                userDetails[user] = IssuerCommand.userData(
                    givenName = givenName,
                    familyName = familyName,
                    gender = gender,
                    birthDate = birthDate,
                    birthCountry = birthCountry
                )
            } else {
                call.respond(HttpStatusCode.BadRequest, "Username and password fields are required")
            }
            call.respondText("The user registered successfully.")
        }
    }

    suspend fun login(call: ApplicationCall, clientID:  MutableMap<String, IssuerCommand.clientIdValues>, clientCredentials: MutableMap<String,String>, userDetails: MutableMap<String,IssuerCommand.userData>) {
        println("\n$verde[+] Issuer: Log in a user.$reset\n")
        val parameters = call.receiveParameters()
        val user = parameters["user"]
        val pass = parameters["pass"]

        log.debug { "loginBackend -> [!] Issuer logs: username - $user password - $pass" }.toString()

        if (user != null && pass != null) {
            if (clientCredentials[user] == pass.sha256()) {

                val clientId = UUID.randomUUID().toString()
                val clientSecret = UUID.randomUUID().toString()
                clientID[clientId] = IssuerCommand.clientIdValues(clientSecret, user)
                val jsonResponse = "{\"clientId\":\"$clientId\", \"clientSecret\":\"$clientSecret\"}"
                call.respondText(jsonResponse, ContentType.Application.Json)

            } else {
                call.respondText("Invalid username or password.", status = io.ktor.http.HttpStatusCode.Unauthorized)
            }
        } else {
            call.respondText("Invalid username or password.", status = io.ktor.http.HttpStatusCode.Unauthorized)
        }

    }
}
