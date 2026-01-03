function togglePassword(button) {
    const passwordField = button.previousElementSibling;
    if (passwordField.type === 'password') {
        passwordField.type = 'text';
        button.textContent = 'Hide';
    } else {
        passwordField.type = 'password';
        button.textContent = 'Show';
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        console.log('Password copied to clipboard');
    }, function(err) {
        console.error('Could not copy password: ', err);
    });
}

function togglePasswordView(accountId) {
    const passwordField = document.getElementById(`pwd-${accountId}`);
    const button = passwordField.nextElementSibling;
    
    if (passwordField.type === 'password') {
        // Fetch and show password
        fetch(`/view_password/${accountId}`)
            .then(response => response.json())
            .then(data => {
                if (data.password) {
                    passwordField.type = 'text';
                    passwordField.value = data.password;
                    button.textContent = 'Hide';
                } else {
                    alert('Failed to decrypt password');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Failed to load password');
            });
    } else {
        // Hide password
        passwordField.type = 'password';
        passwordField.value = '••••••••••••••••';
        button.textContent = 'Show';
    }
}

function copyPassword(accountId) {
    const passwordField = document.getElementById(`pwd-${accountId}`);
    
    if (passwordField.type === 'password') {
        // Need to fetch password first
        fetch(`/view_password/${accountId}`)
            .then(response => response.json())
            .then(data => {
                if (data.password) {
                    copyToClipboard(data.password);
                    // Briefly show confirmation
                    const button = passwordField.nextElementSibling.nextElementSibling;
                    const originalText = button.textContent;
                    button.textContent = 'Copied!';
                    setTimeout(() => {
                        button.textContent = originalText;
                    }, 2000);
                } else {
                    alert('Failed to decrypt password');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Failed to copy password');
            });
    } else {
        // Password is already visible
        copyToClipboard(passwordField.value);
        const button = passwordField.nextElementSibling.nextElementSibling;
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        setTimeout(() => {
            button.textContent = originalText;
        }, 2000);
    }
}