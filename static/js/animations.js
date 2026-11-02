/**
 * Enhanced animations and transitions inspired by hissn.net
 */

document.addEventListener('DOMContentLoaded', function() {
    initEnhancedAnimations();
    initTextRevealEffect();
    initParallaxEffect();
    initSmoothScrolling();
    initTiltEffect();
    initRippleEffect();
});

/**
 * Initialize enhanced scroll-triggered animations
 */
function initEnhancedAnimations() {
    // Animation classes to observe
    const animationClasses = [
        '.fade-scale-up',
        '.slide-up-ease',
        '.slide-down-ease',
        '.blur-in',
        '.staggered-item'
    ];
    
    // Create a single IntersectionObserver for all animations
    const observerOptions = { 
        threshold: 0.1,
        rootMargin: '0px 0px -10% 0px' // Trigger slightly before element comes into view
    };

    const animationObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                // Add 'animated' class which will trigger the animation
                entry.target.classList.add('animated');
                
                // For elements with specific animation classes, set animation play state
                if (entry.target.classList.contains('fade-scale-up') ||
                    entry.target.classList.contains('slide-up-ease') ||
                    entry.target.classList.contains('slide-down-ease') ||
                    entry.target.classList.contains('blur-in')) {
                    entry.target.style.animationPlayState = 'running';
                }
                
                // Unobserve after animation is triggered
                animationObserver.unobserve(entry.target);
            }
        });
    }, observerOptions);

    // Select all elements with animation classes and observe them
    animationClasses.forEach(className => {
        const elements = document.querySelectorAll(className);
        elements.forEach(el => {
            // Pause animations initially
            if (className !== '.staggered-item') {
                el.style.animationPlayState = 'paused';
            }
            animationObserver.observe(el);
        });
    });
    
    // Special handling for staggered grid/list items
    const staggeredContainers = document.querySelectorAll('.staggered-container');
    staggeredContainers.forEach(container => {
        // When container comes into view, add animated class to children with delay
        const containerObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const children = container.querySelectorAll('.staggered-item');
                    children.forEach((child, index) => {
                        setTimeout(() => {
                            child.classList.add('animated');
                        }, index * 100); // 100ms delay between each item
                    });
                    containerObserver.unobserve(container);
                }
            });
        }, observerOptions);
        
        containerObserver.observe(container);
    });
}

/**
 * Initialize text reveal effect for headings
 */
function initTextRevealEffect() {
    const textRevealElements = document.querySelectorAll('.text-reveal');
    
    textRevealElements.forEach(element => {
        // Get the text content
        const text = element.textContent;
        // Clear the element
        element.textContent = '';
        
        // Create a span for each character with increasing delay
        [...text].forEach((char, index) => {
            const span = document.createElement('span');
            span.textContent = char;
            span.style.setProperty('--char-index', index);
            element.appendChild(span);
        });
    });
}

/**
 * Initialize parallax scrolling effect
 */
function initParallaxEffect() {
    const parallaxElements = document.querySelectorAll('.parallax');
    
    window.addEventListener('scroll', () => {
        const scrollTop = window.pageYOffset;
        
        parallaxElements.forEach(element => {
            const speed = element.dataset.speed || 0.5;
            const offset = scrollTop * speed;
            element.style.transform = `translateY(${offset}px)`;
        });
    });
}

/**
 * Initialize smooth scrolling for anchor links
 */
function initSmoothScrolling() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                // Smooth scroll to target
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

/**
 * Initialize tilt effect for cards and images
 */
function initTiltEffect() {
    const tiltElements = document.querySelectorAll('.tilt-hover');
    
    tiltElements.forEach(element => {
        element.addEventListener('mousemove', (e) => {
            const rect = element.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            const centerX = rect.width / 2;
            const centerY = rect.height / 2;
            
            const deltaX = (x - centerX) / centerX;
            const deltaY = (y - centerY) / centerY;
            
            const tiltX = deltaY * 5; // Max 5 degrees
            const tiltY = -deltaX * 5; // Max 5 degrees
            
            element.style.transform = `perspective(1000px) rotateX(${tiltX}deg) rotateY(${tiltY}deg)`;
        });
        
        element.addEventListener('mouseleave', () => {
            element.style.transform = 'perspective(1000px) rotateX(0) rotateY(0)';
        });
    });
}

/**
 * Initialize ripple effect for buttons
 */
function initRippleEffect() {
    const rippleButtons = document.querySelectorAll('.ripple-button');
    
    rippleButtons.forEach(button => {
        button.addEventListener('click', (e) => {
            const rect = button.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            const ripple = document.createElement('span');
            ripple.classList.add('ripple-effect');
            ripple.style.left = `${x}px`;
            ripple.style.top = `${y}px`;
            
            button.appendChild(ripple);
            
            // Remove ripple after animation completes
            setTimeout(() => {
                ripple.remove();
            }, 600);
        });
    });
}
