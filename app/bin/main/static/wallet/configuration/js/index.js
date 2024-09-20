document.addEventListener("DOMContentLoaded", function () {
    fetch('/wallet/Config')
            .then(response => {
                if (!response.ok) {
                    return response.text(); // Leer la respuesta como texto si no es ok
                }
                return response.json(); // Procesar como JSON si es ok
            })
            .then(data => {
                if (typeof data === 'string' && data.startsWith("Error:")) {
                    const errorMessage = data.substring(6).trim(); // Extraer mensaje de error
                    window.location.href = `/wallet/error?error=${encodeURIComponent(errorMessage)}`;
                } else {
                    const metadataDiv = document.getElementById('metadata');
                    metadataDiv.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
                }
            })
            .catch(error => {
                console.error('Error fetching metadata:', error);
                // Manejar el error si la respuesta no es texto plano y la solicitud falla
                const metadataDiv = document.getElementById('metadata');
                metadataDiv.innerHTML = `<p style="color: red;">Error fetching metadata.</p>`;
            });
});
