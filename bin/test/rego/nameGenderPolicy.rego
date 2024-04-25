package system

default main = false

main {
    input.credentialData.credentialSubject.firstName == "Pedro"
    input.credentialData.credentialSubject.gender == "male"
}
