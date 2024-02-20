document.addEventListener('DOMContentLoaded', function() {
    // Extracción de parámetros de la URL
    const urlParams = new URLSearchParams(window.location.search);
    const clientId = urlParams.get('clientId');
    const templateName = urlParams.get('template');

    if (templateName) {
        // Asumimos que el archivo JSON está en la carpeta 'templates' y su nombre coincide con 'templateName'
        fetch(`templates/${templateName}.json`)
            .then(response => response.json())
            .then(data => {
                buildForm(data, clientId, templateName);
            })
            .catch(error => {
                console.error('Error al cargar la plantilla:', error);
                displayMessage('Error al cargar la plantilla. Por favor, revise la consola para más detalles.');
            });
    }
});

function buildForm(template, clientId, templateName) {
    const formContainer = document.getElementById('dynamicForm');
    formContainer.innerHTML = ''; // Limpia el contenedor del formulario

    const form = document.createElement('form');
    form.onsubmit = function(event) {
        event.preventDefault(); // Evita el comportamiento por defecto del formulario

        let userData = {};
        Object.keys(template.credentialSubject).forEach(key => {
            userData[key] = form[key].value;
        });



        // Envía la solicitud POST al endpoint de la API
        fetch('https://localhost:8443/authCode', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                clientId: clientId,
                type: templateName,
                template: userData // Directamente enviamos el objeto userData como parte del JSON.
            })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.text();
        })
        .then(data => {
            displayMessage(`Auth Code: ${data}`); 
        })
        .catch(error => {
            console.error('Error durante la solicitud POST:', error);
            displayMessage('Error durante la solicitud POST. Por favor, revise la consola para más detalles.');
        });
    };

    // Creación dinámica del formulario basado en la plantilla JSON
    Object.keys(template.credentialSubject).forEach(key => {
        const inputGroup = document.createElement('div');
        inputGroup.classList.add('input-group');

        const label = document.createElement('label');
        label.setAttribute('for', key);
        label.textContent = key;
        inputGroup.appendChild(label);

        const input = document.createElement('input');
        input.setAttribute('type', 'text');
        input.setAttribute('name', key);
        input.setAttribute('id', key); // Asegúrate de que el 'id' y el 'for' del label coincidan
        inputGroup.appendChild(input);

        form.appendChild(inputGroup);
    });

    const submitButton = document.createElement('input');
    submitButton.setAttribute('type', 'submit');
    submitButton.setAttribute('value', 'Enviar');
    form.appendChild(submitButton);

    formContainer.appendChild(form);
}

function displayMessage(message) {
    // Busca un contenedor de mensajes existente o crea uno nuevo si no existe
    let messageContainer = document.getElementById('messageContainer');
    if (!messageContainer) {
        messageContainer = document.createElement('div');
        messageContainer.setAttribute('id', 'messageContainer');
        document.body.appendChild(messageContainer);
    }
    
    // Actualiza el contenido del contenedor de mensajes
    messageContainer.textContent = message;
}
