package system

default main = false

main {
    input.credentialData.credentialSubject.givenName == "Pedro"
    input.credentialData.credentialSubject.gender == "Male"
}
