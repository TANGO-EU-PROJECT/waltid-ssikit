document.addEventListener('DOMContentLoaded', function() {

        fetch('/createCredential', { method: 'GET' }) // Asumimos GET para la simplificación
                .then(response => response.json())
                .then(data => showModal(data))
                .catch(error => {
                    if (typeof error === 'string' && error.startsWith("Error:")) {
                        const errorMessage = error.substring(6).trim();
                        window.location.href = `/error?error=${encodeURIComponent(errorMessage)}`;
                    }

                });

});

function showModal(credential) {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
      <div class="modal-content">
        <h2>Detalles de la Credencial</h2>
        <div class="credential-body">
          <pre>${JSON.stringify(credential, null, 2)}</pre>
        </div>
        <div class="modal-buttons">
          <input type="text" class="form-control" id="credentialName" placeholder="Nombre de la credencial">
          <button class="save-button" id="saveButton">Guardar</button>
          <button class="discard-button" onclick="discardCredential()">Eliminar</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);

    document.getElementById('saveButton').onclick = function() {
        const credentialName = document.getElementById('credentialName').value;
        saveCredential(JSON.stringify(credential, null, 2));
    };
}

function saveCredential(credential) {
    const credentialName = document.getElementById('credentialName').value;
    if (!credentialName) {
        alert('Por favor, ingrese un nombre para la credencial.');
        return;
    }

    let jsonObject = JSON.parse(credential);
    jsonObject["name"] = credentialName;
    let credentialToSend = JSON.stringify(jsonObject);

    const formData = new FormData();
    formData.append('credential', credentialToSend);
    formData.append('nameCred', credentialName);

    fetch('/storeCredential', {
        method: 'POST',
        body: formData
    })
            .then(response => response.text())
            .then(text => {
                console.log('Credencial guardada: ', text);
                closeModal();
                const urlParams = new URLSearchParams(window.location.search);
                const redirectUri = urlParams.get('redirecturi');

                if(redirectUri)  window.location.href = redirectUri
                else window.location.href = "/credentials"

            })
            .catch(error => {

                console.error('Error:', error);
            });

}

function discardCredential() {
    console.log('Credencial descartada');
    closeModal();
    window.location.href = "/"
}

function closeModal() {
    const modal = document.querySelector('.modal');
    modal.remove();
}
