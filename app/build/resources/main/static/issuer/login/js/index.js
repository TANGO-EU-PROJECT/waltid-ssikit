document.addEventListener("DOMContentLoaded", function() {
    document.getElementById("loginForm").addEventListener("submit", function(e) {
        e.preventDefault(); // Prevenir la acción por defecto del formulario

        const messageContainer = document.getElementById('messageContainer');
        messageContainer.textContent = ''; // Limpiar mensajes anteriores

        // Preparar los datos del formulario para enviar
        const formData = new FormData();
        formData.append('user', document.getElementById("username").value);
        formData.append('pass', document.getElementById("password").value);

        // Realizar la solicitud POST al servidor
        fetch('/issuer/loginBackend', {
            method: 'POST',
            body: formData,
            credentials: 'include' // Necesario para recibir/setear cookies
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Invalid username or password');
            }
            return response.json(); // Suponiendo que la respuesta es un JSON
        })
        .then(({ clientId, clientSecret }) => {
            // Guardar clientId y clientSecret como cookies
            document.cookie = `clientId-umu-issuer=${clientId}; path=/; samesite=None; Secure`;
            document.cookie = `clientSecret-umu-issuer=${clientSecret}; path=/; samesite=None; Secure`;


            messageContainer.textContent = 'Login successful.';
            messageContainer.style.color = 'green';

           window.location.href =  `/issuer/`

        })
        .catch(error => {
            messageContainer.textContent = error.message;
            messageContainer.style.color = 'red';
        });
    });
});

function redirectToWebWallet(clientId, clientSecret) {
    // Configurar los valores de los inputs
    document.getElementById('clientIdInput').value = clientId;
    document.getElementById('clientSecretInput').value = clientSecret;
  
    // Enviar el formulario
    document.getElementById('redirectForm').submit();
  }
