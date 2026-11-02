/**
 * PhishGuard - Main JavaScript File
 * Contains all the interactive functionality for the PhishGuard application
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize animations for elements with animate-on-scroll class
    initAnimations();
    
    // Initialize tooltips
    initTooltips();
    
    // Initialize URL validation
    initUrlValidation();
    
    // Initialize charts if they exist on the page
    initCharts();
    
    // Initialize copy to clipboard functionality
    initClipboard();
    
    // Initialize password strength meter
    initPasswordStrength();
});

/**
 * Initialize animations for elements that should animate when scrolled into view
 */
function initAnimations() {
    const animateElements = document.querySelectorAll('.animate-on-scroll');
    
    if (animateElements.length > 0) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animated');
                }
            });
        }, { threshold: 0.1 });
        
        animateElements.forEach(element => {
            observer.observe(element);
        });
    }
}

/**
 * Initialize Bootstrap tooltips
 */
function initTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Initialize URL validation for the scan form
 */
function initUrlValidation() {
    const urlForm = document.getElementById('url-scan-form');
    const urlInput = document.getElementById('url-input');
    const urlFeedback = document.getElementById('url-feedback');
    
    if (urlForm && urlInput) {
        urlForm.addEventListener('submit', function(e) {
            if (!isValidUrl(urlInput.value)) {
                e.preventDefault();
                urlInput.classList.add('is-invalid');
                if (urlFeedback) {
                    urlFeedback.textContent = 'Please enter a valid URL (e.g., https://example.com)';
                }
            } else {
                urlInput.classList.remove('is-invalid');
                urlInput.classList.add('is-valid');
            }
        });
        
        urlInput.addEventListener('input', function() {
            if (urlInput.classList.contains('is-invalid')) {
                if (isValidUrl(urlInput.value)) {
                    urlInput.classList.remove('is-invalid');
                    urlInput.classList.add('is-valid');
                    if (urlFeedback) {
                        urlFeedback.textContent = '';
                    }
                }
            }
        });
    }
}

/**
 * Check if a string is a valid URL
 * @param {string} url - The URL to validate
 * @returns {boolean} - Whether the URL is valid
 */
function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Initialize charts on the dashboard page
 */
function initCharts() {
    // Check if Chart.js is loaded
    if (typeof Chart === 'undefined') return;
    
    // Phishing Detection Results Chart
    const resultsChartEl = document.getElementById('resultsChart');
    if (resultsChartEl) {
        new Chart(resultsChartEl, {
            type: 'doughnut',
            data: {
                labels: ['Safe', 'Phishing', 'Suspicious'],
                datasets: [{
                    data: [65, 25, 10],
                    backgroundColor: ['#2ecc71', '#e74c3c', '#f39c12'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                },
                cutout: '70%',
                animation: {
                    animateScale: true,
                    animateRotate: true
                }
            }
        });
    }
    
    // Monthly Scans Chart
    const scansChartEl = document.getElementById('scansChart');
    if (scansChartEl) {
        new Chart(scansChartEl, {
            type: 'line',
            data: {
                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
                datasets: [{
                    label: 'Scans',
                    data: [65, 59, 80, 81, 56, 55, 40, 45, 60, 70, 75, 90],
                    fill: true,
                    backgroundColor: 'rgba(52, 152, 219, 0.2)',
                    borderColor: '#3498db',
                    tension: 0.4,
                    pointBackgroundColor: '#3498db',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                },
                animation: {
                    duration: 2000,
                    easing: 'easeOutQuart'
                }
            }
        });
    }
    
    // Feature Importance Chart
    const featureChartEl = document.getElementById('featureChart');
    if (featureChartEl) {
        new Chart(featureChartEl, {
            type: 'bar',
            data: {
                labels: ['URL Length', 'Domain Age', 'HTTPS', 'IP Address', 'Redirects', 'Prefix/Suffix', 'TinyURL', 'iFrame', 'Mouse Over', 'Right Click'],
                datasets: [{
                    label: 'Feature Importance',
                    data: [0.85, 0.78, 0.72, 0.68, 0.65, 0.62, 0.58, 0.55, 0.52, 0.48],
                    backgroundColor: [
                        'rgba(52, 152, 219, 0.8)',
                        'rgba(52, 152, 219, 0.75)',
                        'rgba(52, 152, 219, 0.7)',
                        'rgba(52, 152, 219, 0.65)',
                        'rgba(52, 152, 219, 0.6)',
                        'rgba(52, 152, 219, 0.55)',
                        'rgba(52, 152, 219, 0.5)',
                        'rgba(52, 152, 219, 0.45)',
                        'rgba(52, 152, 219, 0.4)',
                        'rgba(52, 152, 219, 0.35)'
                    ],
                    borderWidth: 0,
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        beginAtZero: true,
                        max: 1,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    },
                    y: {
                        grid: {
                            display: false
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                },
                animation: {
                    delay: function(context) {
                        return context.dataIndex * 100;
                    },
                    duration: 1000,
                    easing: 'easeOutQuart'
                }
            }
        });
    }
}

/**
 * Initialize copy to clipboard functionality
 */
function initClipboard() {
    const copyButtons = document.querySelectorAll('.copy-btn');
    
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const textToCopy = this.getAttribute('data-copy');
            const originalText = this.innerHTML;
            
            navigator.clipboard.writeText(textToCopy).then(() => {
                this.innerHTML = '<i class="fas fa-check"></i> Copied!';
                setTimeout(() => {
                    this.innerHTML = originalText;
                }, 2000);
            }).catch(err => {
                console.error('Could not copy text: ', err);
            });
        });
    });
}

/**
 * Initialize password strength meter
 */
function initPasswordStrength() {
    const passwordInput = document.getElementById('password');
    const strengthMeter = document.getElementById('password-strength-meter');
    const strengthText = document.getElementById('password-strength-text');
    
    if (passwordInput && strengthMeter) {
        passwordInput.addEventListener('input', function() {
            const strength = calculatePasswordStrength(this.value);
            
            // Update the strength meter
            strengthMeter.value = strength.score;
            
            // Update the text and color
            if (strengthText) {
                strengthText.textContent = strength.message;
                
                // Remove all classes and add the appropriate one
                strengthText.className = '';
                strengthText.classList.add('password-strength-text');
                strengthText.classList.add(`strength-${strength.score}`);
            }
        });
    }
}

/**
 * Calculate password strength
 * @param {string} password - The password to evaluate
 * @returns {Object} - Object containing score (0-4) and message
 */
function calculatePasswordStrength(password) {
    // Default result
    let result = {
        score: 0,
        message: 'Very Weak'
    };
    
    if (!password) {
        return result;
    }
    
    // Calculate score based on various criteria
    let score = 0;
    
    // Length check
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    
    // Complexity checks
    if (/[A-Z]/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    
    // Variety check
    const uniqueChars = new Set(password).size;
    if (uniqueChars >= password.length * 0.7) score += 1;
    
    // Normalize score to 0-4 range
    score = Math.min(Math.floor(score / 2), 4);
    
    // Set message based on score
    const messages = [
        'Very Weak',
        'Weak',
        'Fair',
        'Good',
        'Strong'
    ];
    
    result.score = score;
    result.message = messages[score];
    
    return result;
}

/**
 * Show loading spinner
 * @param {string} elementId - ID of the element to show spinner in
 * @param {string} message - Optional loading message
 */
function showLoading(elementId, message = 'Loading...') {
    const element = document.getElementById(elementId);
    if (element) {
        const spinner = `
            <div class="text-center p-4">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <p class="mt-2">${message}</p>
            </div>
        `;
        element.innerHTML = spinner;
    }
}

/**
 * Hide loading spinner and show content
 * @param {string} elementId - ID of the element containing spinner
 * @param {string} content - HTML content to replace spinner with
 */
function hideLoading(elementId, content) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = content;
    }
}

/**
 * Format a date string
 * @param {string} dateString - ISO date string
 * @returns {string} - Formatted date string
 */
function formatDate(dateString) {
    const options = { year: 'numeric', month: 'long', day: 'numeric' };
    return new Date(dateString).toLocaleDateString(undefined, options);
}

/**
 * Format a time string
 * @param {string} dateString - ISO date string
 * @returns {string} - Formatted time string
 */
function formatTime(dateString) {
    const options = { hour: '2-digit', minute: '2-digit' };
    return new Date(dateString).toLocaleTimeString(undefined, options);
}

/**
 * Format a datetime string
 * @param {string} dateString - ISO date string
 * @returns {string} - Formatted datetime string
 */
function formatDateTime(dateString) {
    return `${formatDate(dateString)} at ${formatTime(dateString)}`;
}

/**
 * Truncate a string to a specified length
 * @param {string} str - String to truncate
 * @param {number} length - Maximum length
 * @returns {string} - Truncated string
 */
function truncateString(str, length = 50) {
    if (str.length <= length) return str;
    return str.substring(0, length) + '...';
}

/**
 * Get domain from URL
 * @param {string} url - URL to extract domain from
 * @returns {string} - Domain name
 */
function getDomain(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname;
    } catch (e) {
        return url;
    }
}

/**
 * Highlight search terms in text
 * @param {string} text - Text to search in
 * @param {string} term - Term to highlight
 * @returns {string} - HTML with highlighted terms
 */
function highlightSearchTerm(text, term) {
    if (!term) return text;
    
    const regex = new RegExp(`(${term})`, 'gi');
    return text.replace(regex, '<mark>$1</mark>');
}