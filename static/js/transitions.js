/**
 * Advanced transitions and effects inspired by hissn.net
 */

document.addEventListener('DOMContentLoaded', function() {
    initPageTransitions();
    initCustomCursor();
    initScrollProgress();
    initRevealOnScroll();
    initSplitText();
    initSpotlightEffect();
    initMagneticEffect();
    init3DCardEffect();
});

/**
 * Initialize smooth page transitions
 */
function initPageTransitions() {
    // Create page transition element if it doesn't exist
    if (!document.querySelector('.page-transition')) {
        const transitionEl = document.createElement('div');
        transitionEl.className = 'page-transition';
        document.body.appendChild(transitionEl);
    }

    // Add visible class to page content
    document.querySelector('.main-content')?.classList.add('page-content', 'visible');

    // Handle link clicks for page transitions
    document.querySelectorAll('a:not([target="_blank"]):not([href^="#"]):not([href^="mailto:"]):not([href^="tel:"])').forEach(link => {
        link.addEventListener('click', function(e) {
            const href = this.getAttribute('href');
            
            // Skip if it's the same page or has no href
            if (!href || href === window.location.pathname) return;
            
            e.preventDefault();
            
            const transitionEl = document.querySelector('.page-transition');
            const pageContent = document.querySelector('.main-content');
            
            // Start transition
            transitionEl.classList.add('active');
            pageContent?.classList.remove('visible');
            
            // Navigate after transition
            setTimeout(() => {
                window.location.href = href;
            }, 600);
        });
    });

    // Handle page load transition
    window.addEventListener('pageshow', function(e) {
        // Don't run animation if navigating back/forward (bfcache)
        if (e.persisted) return;
        
        const transitionEl = document.querySelector('.page-transition');
        
        // Start with transition active
        transitionEl.classList.add('active');
        
        // Then remove it to animate out
        setTimeout(() => {
            transitionEl.classList.remove('active');
            transitionEl.classList.add('exit');
            
            // Reset after animation
            setTimeout(() => {
                transitionEl.classList.remove('exit');
                document.querySelector('.main-content')?.classList.add('visible');
            }, 600);
        }, 10);
    });
}

/**
 * Initialize custom cursor effect
 */
function initCustomCursor() {
    // Only on desktop
    if (window.innerWidth <= 768) return;
    
    // Create cursor elements
    const cursor = document.createElement('div');
    cursor.className = 'custom-cursor';
    document.body.appendChild(cursor);
    
    // Track mouse movement
    document.addEventListener('mousemove', e => {
        cursor.style.left = `${e.clientX}px`;
        cursor.style.top = `${e.clientY}px`;
    });
    
    // Add hover effect on interactive elements
    const interactiveElements = document.querySelectorAll('a, button, .card, .feature-card, [role="button"]');
    interactiveElements.forEach(el => {
        el.addEventListener('mouseenter', () => {
            cursor.classList.add('hover');
        });
        
        el.addEventListener('mouseleave', () => {
            cursor.classList.remove('hover');
        });
    });
    
    // Optional: Add cursor trail effect
    let trail = [];
    const trailLength = 5;
    
    for (let i = 0; i < trailLength; i++) {
        const trailDot = document.createElement('div');
        trailDot.className = 'cursor-trail';
        trailDot.style.opacity = 1 - (i / trailLength);
        document.body.appendChild(trailDot);
        trail.push(trailDot);
    }
    
    let trailPositions = Array(trailLength).fill({ x: 0, y: 0 });
    
    document.addEventListener('mousemove', e => {
        // Update positions array
        trailPositions.pop();
        trailPositions.unshift({ x: e.clientX, y: e.clientY });
        
        // Update trail elements
        trail.forEach((dot, index) => {
            const pos = trailPositions[index];
            dot.style.left = `${pos.x}px`;
            dot.style.top = `${pos.y}px`;
        });
    });
}

/**
 * Initialize scroll progress indicator
 */
function initScrollProgress() {
    // Create progress bar if it doesn't exist
    if (!document.querySelector('.scroll-progress')) {
        const progressBar = document.createElement('div');
        progressBar.className = 'scroll-progress';
        document.body.appendChild(progressBar);
    }
    
    const progressBar = document.querySelector('.scroll-progress');
    
    // Update progress on scroll
    window.addEventListener('scroll', () => {
        const scrollTop = document.documentElement.scrollTop || document.body.scrollTop;
        const scrollHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
        const progress = (scrollTop / scrollHeight) * 100;
        
        progressBar.style.width = `${progress}%`;
    });
}

/**
 * Initialize reveal on scroll effect
 */
function initRevealOnScroll() {
    const revealElements = document.querySelectorAll('.reveal-on-scroll');
    
    if (revealElements.length === 0) return;
    
    const revealObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                revealObserver.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1 });
    
    revealElements.forEach(el => {
        revealObserver.observe(el);
    });
}

/**
 * Initialize split text animation
 */
function initSplitText() {
    const splitTextElements = document.querySelectorAll('.split-text');
    
    splitTextElements.forEach(element => {
        // Get the text content
        const text = element.textContent;
        // Clear the element
        element.textContent = '';
        
        // Create a span for each word
        text.split(' ').forEach(word => {
            const wordSpan = document.createElement('span');
            wordSpan.textContent = word + ' ';
            wordSpan.style.transitionDelay = `${Math.random() * 0.5}s`;
            element.appendChild(wordSpan);
        });
        
        // Observe for scroll reveal
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('visible');
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.1 });
        
        observer.observe(element);
    });
}

/**
 * Initialize spotlight hover effect
 */
function initSpotlightEffect() {
    const spotlightElements = document.querySelectorAll('.spotlight');
    
    spotlightElements.forEach(element => {
        element.addEventListener('mousemove', e => {
            const rect = element.getBoundingClientRect();
            const x = ((e.clientX - rect.left) / rect.width) * 100;
            const y = ((e.clientY - rect.top) / rect.height) * 100;
            
            element.style.setProperty('--x', `${x}%`);
            element.style.setProperty('--y', `${y}%`);
        });
    });
}

/**
 * Initialize magnetic hover effect
 */
function initMagneticEffect() {
    const magneticElements = document.querySelectorAll('.magnetic');
    
    magneticElements.forEach(element => {
        element.addEventListener('mousemove', e => {
            const rect = element.getBoundingClientRect();
            const x = e.clientX - rect.left - rect.width / 2;
            const y = e.clientY - rect.top - rect.height / 2;
            
            // Adjust the strength of the effect
            const strength = 15;
            const magnetX = (x / rect.width) * strength;
            const magnetY = (y / rect.height) * strength;
            
            element.style.transform = `translate(${magnetX}px, ${magnetY}px)`;
        });
        
        element.addEventListener('mouseleave', () => {
            element.style.transform = 'translate(0, 0)';
        });
    });
}

/**
 * Initialize 3D card flip effect
 */
function init3DCardEffect() {
    const cards3D = document.querySelectorAll('.card-3d');
    
    cards3D.forEach(card => {
        // Make sure the card has front and back content
        if (!card.querySelector('.card-3d-content') || !card.querySelector('.card-3d-back')) {
            return;
        }
        
        // Add click event to flip the card
        card.addEventListener('click', () => {
            card.classList.toggle('flipped');
        });
    });
}

/**
 * Add parallax effect to an element
 * @param {HTMLElement} element - The element to add parallax to
 * @param {number} speed - The parallax speed (default: 0.5)
 */
function addParallaxEffect(element, speed = 0.5) {
    if (!element) return;
    
    // Add parallax class
    element.classList.add('parallax');
    
    // Get background image if it exists
    const bgImage = getComputedStyle(element).backgroundImage;
    
    if (bgImage && bgImage !== 'none') {
        // Create parallax background element
        const bgElement = document.createElement('div');
        bgElement.className = 'parallax-bg';
        bgElement.style.backgroundImage = bgImage;
        
        // Remove background from original element
        element.style.backgroundImage = 'none';
        
        // Insert background element
        element.insertBefore(bgElement, element.firstChild);
        
        // Set data-speed attribute
        bgElement.setAttribute('data-speed', speed);
        
        // Add to parallax elements
        document.querySelectorAll('.parallax-bg').forEach(bg => {
            bg.style.transform = `translateY(0)`;
        });
    }
}

/**
 * Create a loading spinner
 * @param {string} type - The type of spinner ('pulse', 'spinner', 'dots')
 * @param {HTMLElement} container - The container to append the spinner to
 * @returns {HTMLElement} - The created spinner element
 */
function createLoadingSpinner(type = 'spinner', container = document.body) {
    let spinner;
    
    switch (type) {
        case 'pulse':
            spinner = document.createElement('div');
            spinner.className = 'pulse-loading';
            break;
            
        case 'dots':
            spinner = document.createElement('div');
            spinner.className = 'dots-loading';
            for (let i = 0; i < 3; i++) {
                const dot = document.createElement('span');
                spinner.appendChild(dot);
            }
            break;
            
        case 'spinner':
        default:
            spinner = document.createElement('div');
            spinner.className = 'spinner-loading';
            break;
    }
    
    container.appendChild(spinner);
    return spinner;
}

/**
 * Create a progress bar
 * @param {HTMLElement} container - The container to append the progress bar to
 * @param {number} initialProgress - Initial progress value (0-100)
 * @returns {Object} - Object with the progress bar element and update function
 */
function createProgressBar(container, initialProgress = 0) {
    const progressBar = document.createElement('div');
    progressBar.className = 'progress-bar';
    
    const progressFill = document.createElement('div');
    progressFill.className = 'progress-bar-fill';
    progressFill.style.width = `${initialProgress}%`;
    
    progressBar.appendChild(progressFill);
    container.appendChild(progressBar);
    
    return {
        element: progressBar,
        update: (progress) => {
            progressFill.style.width = `${progress}%`;
        }
    };
}