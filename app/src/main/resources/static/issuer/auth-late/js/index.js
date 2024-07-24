document.addEventListener("DOMContentLoaded", function() {
    const modal = document.getElementById("modal");
    const modalBody = document.getElementById("modal-body");
    const closeModal = document.getElementsByClassName("close")[0];

    document.getElementById("registerBtn").onclick = function() {
        modalBody.innerHTML = `
                <div class="form-wrapper">
                    <h2>Register</h2>
                    <div id="messageContainer"></div>
                    <form id="registerForm">
                        <div class="input-group">
                            <label for="newUsername">Username</label>
                            <input type="text" id="newUsername" name="user" required>
                        </div>
                        <div class="input-group">
                            <label for="newPassword">Password</label>
                            <input type="password" id="newPassword" name="pass" required>
                        </div>
                        <div class="input-group">
                            <label for="givenName">Given Name</label>
                            <input type="text" id="givenName" name="givenName" required>
                        </div>
                        <div class="input-group">
                            <label for="familyName">Family Name</label>
                            <input type="text" id="familyName" name="familyName" required>
                        </div>
                        <div class="input-group">
                            <label for="gender">Gender</label>
                            <input type="text" id="gender" name="gender" required>
                        </div>
                        <div class="input-group">
                            <label for="birthDate">Birth Date</label>
                            <input type="date" id="birthDate" name="birthDate" required>
                        </div>
                        <div class="input-group">
                            <label for="birthCountry">Birth Country</label>
                            <input type="text" id="birthCountry" name="birthCountry" required>
                        </div>
                        <input type="submit" value="Register">
                    </form>
                    <p class="login-link">Already have an account? <a href="#" id="switchToLogin">Login here</a></p>
                </div>
            `;
        modal.style.display = "block";

        document.getElementById("registerForm").addEventListener("submit", function(e) {
            e.preventDefault();
            const messageContainer = document.getElementById('messageContainer');
            messageContainer.textContent = '';
            const formData = new FormData(this);
            fetch('/issuer/registerBackend', {
                method: 'POST',
                body: formData
            })
                    .then(response => response.text())
                    .then(text => {
                        if (text.includes("successfully")) {
                            messageContainer.textContent = 'Registration successful. You can now log in.';
                            messageContainer.style.color = 'green';
                            document.getElementById("switchToLogin").click();
                        } else {
                            messageContainer.textContent = 'Registration failed: ' + text;
                            messageContainer.style.color = 'red';
                        }
                    })
                    .catch(error => {
                        messageContainer.textContent = 'An error occurred while registering.';
                        messageContainer.style.color = 'red';
                    });
        });

        document.getElementById("switchToLogin").onclick = function(e) {
            e.preventDefault();
            document.getElementById("loginBtn").click();
        };
    };

    document.getElementById("loginBtn").onclick = function() {
        modalBody.innerHTML = `
                <div class="form-wrapper">
                    <h2>Login</h2>
                    <div id="messageContainer"></div>
                    <form id="loginForm">
                        <div class="input-group">
                            <label for="username">Username</label>
                            <input type="text" id="username" name="username" required>
                        </div>
                        <div class="input-group">
                            <label for="password">Password</label>
                            <input type="password" id="password" name="password" required>
                        </div>
                        <input type="submit" value="Login">
                    </form>
                    <p class="register-link">Don't have an account? <a href="#" id="switchToRegister">Register for an account</a></p>
                </div>
            `;
        modal.style.display = "block";

        document.getElementById("loginForm").addEventListener("submit", function(e) {
            e.preventDefault();
            const messageContainer = document.getElementById('messageContainer');
            messageContainer.textContent = '';
            const formData = new FormData();
            formData.append('user', document.getElementById("username").value);
            formData.append('pass', document.getElementById("password").value);
            fetch('/issuer/loginBackend', {
                method: 'POST',
                body: formData,
                credentials: 'include'
            })
                    .then(response => {
                        if (!response.ok) {
                            throw new Error('Invalid username or password');
                        }
                        return response.json();
                    })
                    .then(({ clientId, clientSecret }) => {
                        document.cookie = `clientId-umu-issuer=${clientId}; path=/; domain=wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu; samesite=None; Secure`;
                        document.cookie = `clientSecret-umu-issuer=${clientSecret}; path=/; domain=wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu; samesite=None; Secure`;

                        const state = new URLSearchParams(window.location.search).get('state');
                        const template = new URLSearchParams(window.location.search).get('template');
                        window.location.href = `/issuer/form?clientId=${clientId}&state=${state}&template=${template}`;
                    })
                    .catch(error => {
                        messageContainer.textContent = error.message;
                        messageContainer.style.color = 'red';
                    });
        });

        document.getElementById("switchToRegister").onclick = function(e) {
            e.preventDefault();
            document.getElementById("registerBtn").click();
        };
    };

    closeModal.onclick = function() {
        modal.style.display = "none";
    };

    window.onclick = function(event) {
        if (event.target == modal) {
            modal.style.display = "none";
        }
    };
});
