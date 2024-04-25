document.addEventListener("DOMContentLoaded", function() {
    document.getElementById("registerForm").addEventListener("submit", function(e) {
        e.preventDefault(); // Prevenir la acción por defecto del formulario

        const messageContainer = document.getElementById('messageContainer');
        messageContainer.textContent = ''; // Limpiar mensajes anteriores

        // Preparar los datos del formulario para enviar
        const formData = new FormData();
        formData.append('user', document.getElementById("newUsername").value);
        formData.append('pass', document.getElementById("newPassword").value);

        // Realizar la solicitud POST al servidor
        fetch('https://umu-issuer:8443/registerBackend', {
            method: 'POST',
            body: formData
        })
        .then(response => response.text()) // Convertir la respuesta en texto
        .then(text => {
            console.log(text); // Mostrar la respuesta del servidor en la consola
            if (text.includes("successfully")) {
                messageContainer.textContent = 'Registration successful. You can now log in.';
                messageContainer.style.color = 'green';
                window.location.href = "/login"; 
            } else {
                messageContainer.textContent = 'Registration failed: ' + text;
                messageContainer.style.color = 'red';
            }
        })
        .catch(error => {
            console.error('Error:', error);
            messageContainer.textContent = 'An error occurred while registering.';
            messageContainer.style.color = 'red';
        });
    });
});
