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
        // Iniciar cada servicio en su propio hilo
        Thread {
            println("Iniciando el servicio Issuer...")
            IssuerCommand().run()
        }.start()

        Thread {
            println("Inicio del bloque init")
            println("Iniciando el servicio Verifier...")
            VerifierCommand().run()
        }.start()

        Thread {
            println("Iniciando el servicio Web Wallet...")
            WebWalletCommand().run()
        }.start()
    }
}

fun main(args: Array<String>) = FullApi().main(args)
