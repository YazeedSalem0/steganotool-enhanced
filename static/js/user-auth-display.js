/**
 * User Authentication Display
 * Handles displaying user authentication status and personalized greetings
 */

document.addEventListener('DOMContentLoaded', function() {
    // Check if user is logged in
    const authToken = localStorage.getItem('auth_token');
    const userName = localStorage.getItem('user_name') || 'User';
    
    // Update navigation based on auth status
    updateNavigation(!!authToken, userName);
    
    // Display welcome message if logged in
    if (authToken) {
        displayWelcomeMessage(userName);
    }
});

/**
 * Update navigation based on authentication status
 */
function updateNavigation(isLoggedIn, userName) {
    const navItems = document.querySelector('.navbar-nav');
    
    if (isLoggedIn) {
        // Remove the Sign In and Sign Up buttons
        const signInItem = document.querySelector('.nav-link[href="/sign-in"]');
        const signUpItem = document.querySelector('.nav-link[href="/sign-up"]');
        
        if (signInItem && signInItem.parentNode) {
            signInItem.parentNode.remove();
        }
        
        if (signUpItem && signUpItem.parentNode) {
            signUpItem.parentNode.remove();
        }
        
        // Add user menu dropdown
        const userMenuItem = document.createElement('li');
        userMenuItem.className = 'nav-item dropdown';
        userMenuItem.innerHTML = `
            <a class="nav-link dropdown-toggle user-menu-link" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                <i class="bi bi-person-circle"></i> ${userName}
            </a>
            <ul class="dropdown-menu dropdown-menu-end">
                <li><a class="dropdown-item" href="#"><i class="bi bi-gear"></i> Settings</a></li>
                <li><hr class="dropdown-divider"></li>
                <li><a class="dropdown-item" href="#" id="logoutButton"><i class="bi bi-box-arrow-right"></i> Logout</a></li>
            </ul>
        `;
        
        navItems.appendChild(userMenuItem);
        
        // Add logout functionality
        document.getElementById('logoutButton').addEventListener('click', function(e) {
            e.preventDefault();
            logout();
        });
    }
}

/**
 * Displays a welcome message for the logged-in user
 * Specially greets Zaid if using the demo account
 */
function displayWelcomeMessage(userName) {
    // Create welcome message element
    const welcomeEl = document.createElement('div');
    welcomeEl.className = 'welcome-banner';
    
    const isDemoAccount = localStorage.getItem('auth_token') === 'demo_token_12345';
    
    // Special greeting for Zaid with the demo account
    if (isDemoAccount) {
        welcomeEl.innerHTML = `
            <div class="container">
                <div class="welcome-content">
                    <i class="bi bi-hand-thumbs-up"></i>
                    <div class="welcome-text">
                        <h3>Hello Moawya!</h3>
                        <p>Welcome to SteganoTool. You're using the demo account. Enjoy exploring our steganography features!</p>
                    </div>
                    <button class="welcome-close"><i class="bi bi-x"></i></button>
                </div>
            </div>
        `;
    } else {
        welcomeEl.innerHTML = `
            <div class="container">
                <div class="welcome-content">
                    <i class="bi bi-hand-thumbs-up"></i>
                    <div class="welcome-text">
                        <h3>Welcome back, ${userName}!</h3>
                        <p>Ready to encrypt and hide some messages today?</p>
                    </div>
                    <button class="welcome-close"><i class="bi bi-x"></i></button>
                </div>
            </div>
        `;
    }
    
    // Insert after navbar
    const navbar = document.querySelector('.navbar');
    navbar.parentNode.insertBefore(welcomeEl, navbar.nextSibling);
    
    // Add close button functionality
    document.querySelector('.welcome-close').addEventListener('click', function() {
        welcomeEl.remove();
    });
}

/**
 * Logout function
 */
function logout() {
    // Clear authentication data
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_name');
    localStorage.removeItem('remember_auth');
    
    // Redirect to home page
    window.location.href = '/';
} 