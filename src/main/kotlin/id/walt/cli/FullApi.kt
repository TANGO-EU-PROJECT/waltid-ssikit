package id.walt.cli

import id.walt.cli.IssuerCommand
import id.walt.cli.VerifierCommand
import id.walt.cli.WebWalletCommand
import com.github.ajalt.clikt.core.CliktCommand

class FullApi :
        CliktCommand(
                name = "fullApi",
                help = "Start all services"
        ) {
    override fun run() {
        val verde = "\u001B[32m"
        val rojo = "\u001B[31m"
        val reset = "\u001B[0m"

        // Iniciar cada servicio en su propio hilo
        Thread {
            println("\n$verde[+] Iniciando el servicio Issuer...\n$reset\n")
            IssuerCommand().run()
        }.start()

        Thread {
            Thread.sleep(3000)
            println("\n$verde[+] Iniciando el servicio verifier...\n$reset\n")
            VerifierCommand().run()
        }.start()

        Thread {
            Thread.sleep(6000)
            println("\n$verde[+] Iniciando el servicio web wallet...\n$reset\n")
            WebWalletCommand().run()
        }.start()
    }
}

fun main(args: Array<String>) = FullApi().main(args)
