


    document.getElementById('credentialType').addEventListener('change', function() {
        var type = this.value;
        if (type) {
            fetch(`../templates/${type}.json`) // Asume una ruta en tu servidor que sirva el JSON
                .then(response => response.json())
                .then(data => {
                    buildForm(data);
                })
                .catch(error => console.error('Error al cargar la plantilla:', error));
        }
    });
    
    function buildForm(template) {
        const formContainer = document.getElementById('dynamicForm');
        formContainer.innerHTML = ''; // Limpia el formulario anterior
    
        const form = document.createElement('form');
        form.setAttribute('action', '/process-info');
        form.setAttribute('method', 'post');
    
        // Construye los campos del formulario basándose en el template
        Object.keys(template.credentialSubject).forEach(key => {
            const inputGroup = document.createElement('div');
    
            const label = document.createElement('label');
            label.setAttribute('for', key);
            label.textContent = key; // Ajusta esto para mejorar la legibilidad
            inputGroup.appendChild(label);
    
            const input = document.createElement('input');
            input.setAttribute('type', 'text');
            input.setAttribute('name', key);
            input.setAttribute('placeholder', key); // Ajusta esto según necesidades
            inputGroup.appendChild(input);
    
            form.appendChild(inputGroup);
        });
    
        const submitButton = document.createElement('input');
        submitButton.setAttribute('type', 'submit');
        submitButton.setAttribute('value', 'Enviar');
        form.appendChild(submitButton);
    
        formContainer.appendChild(form);
    }
    