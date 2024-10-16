// Handle signup form submission
document.getElementById('signup-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    // Grab values from the signup form
    const name = document.getElementById('name').value;
    const email = document.getElementById('signup-email').value;  // Updated ID
    const password = document.getElementById('signup-password').value;  // Updated ID
    const role = document.getElementById('role').value;  // Ensure this exists

    try {
        const response = await fetch('/signup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ name, email, password, role }),
        });
        const data = await response.json();
        if (response.ok) {
            alert('Signup successful! Check your email for verification.');
            window.location.href = '/login';
        } else {
            alert(data.error || 'Signup failed.');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Signup failed due to a network error.');
    }
});

// Handle login form submission
document.getElementById('login-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    // Grab values from the login form
    const email = document.getElementById('login-email').value;  // Updated ID
    const password = document.getElementById('login-password').value;  // Updated ID

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password }),
        });
        const data = await response.json();
        if (response.ok) {
            alert('Login successful!');
            window.location.href = '/';  // Redirect to home page
        } else {
            alert(data.error || 'Login failed.');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Login failed due to a network error.');
    }
});
