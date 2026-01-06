// Password Manager JavaScript utilities

function togglePasswordVisibility(inputId, button) {
    const input = document.getElementById(inputId);
    if (input.type === 'password') {
        input.type = 'text';
        button.innerHTML = 'Hide';
        button.title = 'Hide password';
    } else {
        input.type = 'password';
        button.innerHTML = 'Show';
        button.title = 'Show password';
    }
}

// Home page password show/hide functionality
function togglePasswordView(accountId) {
    const input = document.getElementById('pwd-' + accountId);
    const button = document.querySelector(`[data-account-id="${accountId}"][onclick*="togglePasswordView"]`);
    
    if (input.type === 'password') {
        // Show password - fetch from server
        fetch('/get_password/' + accountId)
            .then(response => response.json())
            .then(data => {
                if (data.password) {
                    input.type = 'text';
                    input.value = data.password;
                    button.textContent = 'Hide';
                } else {
                    alert('Error loading password');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error loading password');
            });
    } else {
        // Hide password
        input.type = 'password';
        input.value = '••••••••••••••••';
        button.textContent = 'Show';
    }
}

function copyPassword(accountId) {
    fetch('/get_password/' + accountId)
        .then(response => response.json())
        .then(data => {
            if (data.password) {
                navigator.clipboard.writeText(data.password).then(() => {
                    const button = document.querySelector(`[data-account-id="${accountId}"][onclick*="copyPassword"]`);
                    const originalText = button.textContent;
                    button.textContent = 'Copied!';
                    button.style.backgroundColor = '#28a745';
                    setTimeout(() => {
                        button.textContent = originalText;
                        button.style.backgroundColor = '';
                    }, 2000);
                }).catch(err => {
                    alert('Failed to copy password to clipboard');
                });
            } else {
                alert('Error loading password');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error loading password');
        });
}

function showThemeSelector() {
    const themeSelector = document.getElementById('themeSelector');
    const customTheme = document.getElementById('customTheme');
    if (themeSelector) {
        themeSelector.style.display = 'block';
    }
    if (customTheme) {
        customTheme.focus();
    }
}

function hideThemeSelector() {
    const themeSelector = document.getElementById('themeSelector');
    const status = document.getElementById('generationStatus');
    const customTheme = document.getElementById('customTheme');
    
    if (themeSelector) {
        themeSelector.style.display = 'none';
    }
    if (status) {
        status.style.display = 'none';
    }
    if (customTheme) {
        customTheme.value = '';
    }
}

function generateCustomThemePassword() {
    const customTheme = document.getElementById('customTheme');
    if (!customTheme) return;
    
    const theme = customTheme.value.trim();
    if (!theme) {
        alert('Please enter a theme first!');
        return;
    }
    generateThemedPassword(theme);
}

function setTheme(theme) {
    const customTheme = document.getElementById('customTheme');
    if (customTheme) {
        customTheme.value = theme;
    }
    generateThemedPassword(theme);
}

async function generateThemedPassword(theme) {
    const passwordField = document.getElementById('password');
    const status = document.getElementById('generationStatus');
    const themeButtons = document.querySelectorAll('.theme-btn, .quick-theme-btn');
    
    if (!passwordField || !status) {
        console.error('Required elements not found');
        return;
    }
    
    // Disable all theme buttons and show loading
    themeButtons.forEach(btn => btn.disabled = true);
    status.style.display = 'block';
    status.style.backgroundColor = '#d1ecf1';
    status.style.color = '#0c5460';
    status.innerHTML = `Generating "${theme}" password...`;
    
    try {
        const response = await fetch('/generate_themed_password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ theme: theme })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            passwordField.value = result.password;
            passwordField.type = 'text'; // Show password briefly
            
            status.style.backgroundColor = '#d4edda';
            status.style.color = '#155724';
            status.innerHTML = `Generated "${theme}" password! Copied to field.`;
            
            // Hide password after 3 seconds
            setTimeout(() => {
                passwordField.type = 'password';
            }, 3000);
            
            // Hide selector after 2 seconds
            setTimeout(() => {
                hideThemeSelector();
            }, 2000);
            
        } else {
            throw new Error(result.error || 'Failed to generate password');
        }
        
    } catch (error) {
        console.error('Error generating themed password:', error);
        
        status.style.backgroundColor = '#f8d7da';
        status.style.color = '#721c24';
        
        if (error.message.includes('API key')) {
            status.innerHTML = 'Please configure your API key in app.py (line with YOUR_API_KEY_HERE)';
        } else {
            status.innerHTML = `Error: ${error.message}`;
        }
    } finally {
        // Re-enable all theme buttons
        themeButtons.forEach(btn => btn.disabled = false);
    }
}

// Add some CSS for better button hover effects and Enter key support
const style = document.createElement('style');
style.textContent = `
    .theme-btn:hover, .quick-theme-btn:hover {
        opacity: 0.8;
        transform: translateY(-1px);
    }
    
    .theme-btn:disabled, .quick-theme-btn:disabled {
        opacity: 0.6;
        cursor: not-allowed;
    }
`;
document.head.appendChild(style);

// Add Enter key support for custom theme input
document.addEventListener('DOMContentLoaded', function() {
    const customThemeInput = document.getElementById('customTheme');
    if (customThemeInput) {
        customThemeInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                generateCustomThemePassword();
            }
        });
    }
});

console.log('Password Manager with dynamic themed generation loaded');