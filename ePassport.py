import jwt
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

html_page = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JWT Sender</title>
</head>
<body>
    <h1>JWT Submission Form</h1>
    <form id="jwtForm">
        <label for="jwt">JWT:</label>
        <input type="text" id="jwt" name="jwt">
        <button type="button" onclick="sendJWT()">Send JWT</button>
    </form>

    <script>
        // Función para obtener el valor de un parámetro de la URL
        function getQueryParam(param) {
            var urlParams = new URLSearchParams(window.location.search);
            return urlParams.get(param);
        }

        // Cargar el JWT en el input si está presente en la URL
        document.addEventListener("DOMContentLoaded", function() {
            var jwt = getQueryParam('jwt');
            if (jwt) {
                document.getElementById('jwt').value = jwt;
            }
        });

        function sendJWT() {
            var jwt = document.getElementById('jwt').value;
            if (jwt) {
                var url = '/send' + '?jwt=' + encodeURIComponent(jwt);
                fetch(url)
                .then(response => response.text())
                .then(data => {
                    window.location.href = data;
                })
                .catch(error => console.error('Error:', error));
            } else {
                alert("Please enter a JWT");
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    # Directly return the HTML page
    return html_page

# Ruta que recibe el JWT
@app.route('/send', methods=['GET'])
def handle_jwt():
    # Extraer el token JWT del parámetro de consulta 'jwt'
    token = request.args.get('jwt')
    if not token:
        return jsonify({'error': 'No JWT provided'}), 400

    # Decodificar el JWT (sin verificar la firma en este ejemplo simple)
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
    except jwt.DecodeError:
        return jsonify({'error': 'Invalid JWT'}), 400

    # Extraer datos del JWT
    redirect_uri = payload.get('redirect_uri')
    client_id = payload.get('sub')
    state = payload.get('state')

    # Preparar los datos para enviar como parámetros de URL
    print(client_id)
    data = {
        'clientId': client_id,
        'state': state,
        'template': {
            'givenName': 'Raul',
            'familyName': 'Fernandez',
            'gender': 'Male',
            'birthDate': '1998-09-12',
            'birthCountry': 'Spain'
        }
    }

    # Headers para asegurar que el Content-Type sea application/json
    headers = {'Content-Type': 'application/json'}

    # Enviar la solicitud POST con la verificación de SSL desactivada
    response = requests.post(redirect_uri, json=data, headers=headers, verify=False)

    print(f"\nCode: {response.text}\n")
    # Retornar la respuesta
    return response.text

if __name__ == '__main__':
    app.run(debug=True)
