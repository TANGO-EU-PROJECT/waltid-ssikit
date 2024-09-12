

document.getElementById('api-endpoint').addEventListener('input', function () {
    //generateQRCode();
});

document.getElementById('send-request').addEventListener('click', async function () {
    const endpoint = document.getElementById('api-endpoint').value;

    if (endpoint.startsWith('http')) {
        fetch('/verifier/vpToken')
                .then(response => response.text())
                .then(vpToken => {
                    const finalUrl = `${endpoint}?vpToken=${encodeURIComponent(vpToken)}`;
                    console.log(finalUrl)
                    window.location.href = finalUrl;
                })
                .catch(error => console.error('Error al obtener el vpToken:', error));
    } else {
        console.error('La respuesta no comienza con "http":', response.data);
    }

});

function generateQRCode() {
    const endpoint = document.getElementById('api-endpoint').value;
    fetch('/verifier/vpToken')
            .then(response => response.text())
            .then(vpToken => {
                console.log(vpToken);
                const finalUrl = `${endpoint}?vpToken=${encodeURIComponent(vpToken)}`;
                document.getElementById("qrcode").innerHTML = "";
                console.log(finalUrl);
                new QRCode(document.getElementById("qrcode"), finalUrl);
            })
            .catch(error => console.error('Error al obtener el vpToken:', error));


}

// Inicializa el QR code al cargar la página
//generateQRCode();
