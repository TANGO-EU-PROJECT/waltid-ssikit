document.addEventListener('DOMContentLoaded', function() {
    const urlParams = new URLSearchParams(window.location.search);
    const templateName = urlParams.get('template');
    const clientId = urlParams.get('clientId');

    if (templateName && clientId) {
        fetch(`/static/issuer/form/templates/${templateName}.json`)
                .then(response => response.json())
                .then(data => {
                    // Realizar una solicitud adicional para obtener datos previamente guardados, si existen
                    fetch(`/getCliendId-data?clientid=${clientId}`)
                            .then(response => response.json())
                            .then(preloadedData => {
                                buildForm(data, preloadedData);
                            })
                            .catch(error => {
                                console.error('Error al pre-cargar los datos:', error);
                                buildForm(data, {});
                            });
                })
                .catch(error => {
                    console.error('Error al cargar la plantilla:', error);
                    displayMessage('Error al cargar la plantilla. Por favor, revise la consola para más detalles.');
                });
    }
});

function buildForm(template, preloadedData) {
    const urlParams = new URLSearchParams(window.location.search);
    const formContainer = document.getElementById('dynamicForm');
    formContainer.innerHTML = '';

    const form = document.createElement('form');
    form.onsubmit = function(event) {
        event.preventDefault();

        let userData = {};
        Object.keys(template.credentialSubject).forEach(key => {
            userData[key] = form[key].value;
        });

        let requestBody = {
            clientId: urlParams.get('clientId'),
            type: urlParams.get('template'),
            template: userData
        };
        let url = "/code"

        if (urlParams.get('state')) {
            requestBody.state = urlParams.get('state');
            url = "/code-late"
        }

        fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody)
        })
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    return response.text();
                })
                .then(uri => {
                    window.location.href = uri;
                })
                .catch(error => {
                    console.error('Error durante la solicitud POST:', error);
                    displayMessage('Error durante la solicitud POST. Por favor, revise la consola para más detalles.');
                });
    };

    // Creación dinámica del formulario basado en la plantilla JSON y datos pre-cargados
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
        input.setAttribute('id', key);
        input.value = preloadedData[key] || ''; // Cargar datos pre-cargados si están disponibles
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
    let messageContainer = document.getElementById('messageContainer');
    if (!messageContainer) {
        messageContainer = document.createElement('div');
        messageContainer.setAttribute('id', 'messageContainer');
        document.body.appendChild(messageContainer);
    }
    messageContainer.textContent = message;
}
