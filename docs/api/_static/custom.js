// Custom JavaScript for CODE API Documentation

/**
 * Memory management utilities for preventing event listener leaks
 */
const MemoryManager = {
    // WeakMap for storing cleanup functions
    cleanupFunctions: new WeakMap(),
    // WeakMap for storing timer references
    timers: new WeakMap(),
    // Set to track all registered event listeners
    eventListeners: new Set(),
    
    /**
     * Register an event listener for cleanup tracking
     * @param {Element} element - The element to add listener to
     * @param {string} event - The event type
     * @param {Function} handler - The event handler
     * @param {Object} options - Event listener options
     */
    addEventListener: function(element, event, handler, options = {}) {
        element.addEventListener(event, handler, options);
        
        const listenerInfo = { element, event, handler, options };
        this.eventListeners.add(listenerInfo);
        
        // Store cleanup function
        const cleanup = () => {
            element.removeEventListener(event, handler, options);
            this.eventListeners.delete(listenerInfo);
        };
        
        const cleanups = this.cleanupFunctions.get(element) || [];
        cleanups.push(cleanup);
        this.cleanupFunctions.set(element, cleanups);
        
        return cleanup;
    },
    
    /**
     * Set a timeout with automatic cleanup tracking
     * @param {Function} callback - The callback function
     * @param {number} delay - Delay in milliseconds
     * @returns {number} Timer ID
     */
    setTimeout: function(callback, delay) {
        const timerId = setTimeout(callback, delay);
        this.timers.set(callback, timerId);
        return timerId;
    },
    
    /**
     * Clear a tracked timeout
     * @param {number} timerId - The timer ID to clear
     */
    clearTimeout: function(timerId) {
        clearTimeout(timerId);
        // Find and remove from timers map
        for (const [callback, id] of this.timers.entries()) {
            if (id === timerId) {
                this.timers.delete(callback);
                break;
            }
        }
    },
    
    /**
     * Clean up all event listeners and timers for an element
     * @param {Element} element - The element to clean up
     */
    cleanup: function(element) {
        const cleanups = this.cleanupFunctions.get(element);
        if (cleanups) {
            cleanups.forEach(cleanup => cleanup());
            this.cleanupFunctions.delete(element);
        }
    },
    
    /**
     * Clean up all registered event listeners and timers
     */
    cleanupAll: function() {
        // Clean up all event listeners
        this.eventListeners.forEach(({ element, event, handler, options }) => {
            element.removeEventListener(event, handler, options);
        });
        this.eventListeners.clear();
        
        // Clear all timers
        this.timers.forEach((timerId) => {
            clearTimeout(timerId);
        });
        this.timers.clear();
        
        // Clear cleanup functions
        this.cleanupFunctions = new WeakMap();
    }
};

// Global cleanup on page unload
MemoryManager.addEventListener(window, 'beforeunload', () => {
    MemoryManager.cleanupAll();
});

// Global cleanup on page hide (for mobile browsers)
MemoryManager.addEventListener(window, 'pagehide', () => {
    MemoryManager.cleanupAll();
});

document.addEventListener('DOMContentLoaded', function() {
    // Add copy buttons to code blocks
    addCopyButtons();
    
    // Add method badges to API endpoints
    addMethodBadges();
    
    // Initialize API examples
    initializeAPIExamples();
    
    // Add status badges
    addStatusBadges();
    
    // Enhance navigation
    enhanceNavigation();
});

/**
 * Add copy buttons to code blocks with proper memory management
 */
function addCopyButtons() {
    const codeBlocks = document.querySelectorAll('.highlight pre');
    
    codeBlocks.forEach(function(block) {
        const copyButton = document.createElement('button');
        copyButton.className = 'copy-button';
        copyButton.textContent = 'Copy';
        copyButton.style.cssText = `
            position: absolute;
            top: 5px;
            right: 5px;
            padding: 4px 8px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
            opacity: 0.8;
        `;
        
        const container = block.parentElement;
        container.style.position = 'relative';
        container.appendChild(copyButton);
        
        // Use MemoryManager for event listeners with proper cleanup
        let copyTimeoutId = null;
        
        const clickHandler = function() {
            const code = block.textContent;
            navigator.clipboard.writeText(code).then(function() {
                copyButton.textContent = 'Copied!';
                
                // Clear existing timeout if any
                if (copyTimeoutId) {
                    MemoryManager.clearTimeout(copyTimeoutId);
                }
                
                copyTimeoutId = MemoryManager.setTimeout(function() {
                    copyButton.textContent = 'Copy';
                    copyTimeoutId = null;
                }, 2000);
            });
        };
        
        const mouseEnterHandler = function() {
            copyButton.style.opacity = '1';
        };
        
        const mouseLeaveHandler = function() {
            copyButton.style.opacity = '0.8';
        };
        
        // Register event listeners with cleanup tracking
        MemoryManager.addEventListener(copyButton, 'click', clickHandler);
        MemoryManager.addEventListener(container, 'mouseenter', mouseEnterHandler);
        MemoryManager.addEventListener(container, 'mouseleave', mouseLeaveHandler);
        
        // Store cleanup function for this button
        const cleanup = () => {
            if (copyTimeoutId) {
                MemoryManager.clearTimeout(copyTimeoutId);
                copyTimeoutId = null;
            }
            MemoryManager.cleanup(copyButton);
            MemoryManager.cleanup(container);
        };
        
        // Store cleanup function in WeakMap
        const cleanups = MemoryManager.cleanupFunctions.get(container) || [];
        cleanups.push(cleanup);
        MemoryManager.cleanupFunctions.set(container, cleanups);
    });
}

function addMethodBadges() {
    // Find headers that contain HTTP methods
    const headers = document.querySelectorAll('h1, h2, h3, h4, h5, h6');
    
    headers.forEach(function(header) {
        const text = header.textContent;
        const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
        
        methods.forEach(function(method) {
            if (text.includes(method + ' ')) {
                const badge = document.createElement('span');
                badge.className = 'method-badge method-' + method.toLowerCase();
                badge.textContent = method;
                header.insertBefore(badge, header.firstChild);
            }
        });
    });
}

function initializeAPIExamples() {
    // Add interactive features to API examples
    const examples = document.querySelectorAll('.highlight');
    
    examples.forEach(function(example) {
        const pre = example.querySelector('pre');
        if (pre && pre.textContent.includes('curl')) {
            addCurlConverter(example);
        }
    });
}

/**
 * Add curl converter with proper memory management
 * @param {Element} example - The example element
 */
function addCurlConverter(example) {
    const convertButton = document.createElement('button');
    convertButton.textContent = 'Convert to Python';
    convertButton.className = 'convert-button';
    convertButton.style.cssText = `
        margin-top: 10px;
        padding: 6px 12px;
        background: #28a745;
        color: white;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-size: 13px;
    `;
    
    example.appendChild(convertButton);
    
    const clickHandler = function() {
        const curlCommand = example.querySelector('pre').textContent;
        const pythonCode = convertCurlToPython(curlCommand);
        
        if (pythonCode) {
            showConvertedCode(example, pythonCode);
        }
    };
    
    // Register event listener with cleanup tracking
    MemoryManager.addEventListener(convertButton, 'click', clickHandler);
}

function convertCurlToPython(curlCommand) {
    // Simple curl to Python requests conversion
    try {
        let pythonCode = 'import requests\n\n';
        
        // Extract URL
        const urlMatch = curlCommand.match(/curl[^"]*"([^"]+)"/);
        if (!urlMatch) return null;
        
        const url = urlMatch[1];
        
        // Extract method
        let method = 'GET';
        if (curlCommand.includes('-X POST')) method = 'POST';
        if (curlCommand.includes('-X PUT')) method = 'PUT';
        if (curlCommand.includes('-X DELETE')) method = 'DELETE';
        
        // Extract headers
        const headerMatches = curlCommand.match(/-H\s+"([^"]+)"/g);
        let headers = {};
        if (headerMatches) {
            headerMatches.forEach(function(match) {
                const header = match.match(/-H\s+"([^"]+)"/)[1];
                const [key, value] = header.split(': ');
                headers[key] = value;
            });
        }
        
        // Extract data
        const dataMatch = curlCommand.match(/-d\s+'([^']+)'/);
        let data = null;
        if (dataMatch) {
            data = dataMatch[1];
        }
        
        // Generate Python code
        pythonCode += `url = "${url}"\n`;
        
        if (Object.keys(headers).length > 0) {
            pythonCode += `headers = ${JSON.stringify(headers, null, 2)}\n`;
        }
        
        if (data) {
            pythonCode += `data = ${data}\n`;
        }
        
        pythonCode += '\nresponse = requests.';
        pythonCode += method.toLowerCase() + '(url';
        
        if (Object.keys(headers).length > 0) {
            pythonCode += ', headers=headers';
        }
        
        if (data) {
            pythonCode += ', json=data';
        }
        
        pythonCode += ')\n';
        pythonCode += 'print(response.json())';
        
        return pythonCode;
    } catch (e) {
        return null;
    }
}

function showConvertedCode(example, pythonCode) {
    // Remove existing converted code
    const existing = example.querySelector('.converted-code');
    if (existing) {
        existing.remove();
        return;
    }
    
    const convertedDiv = document.createElement('div');
    convertedDiv.className = 'converted-code';
    convertedDiv.style.cssText = `
        margin-top: 15px;
        border: 1px solid #28a745;
        border-radius: 4px;
        background: #f8fff8;
    `;
    
    const header = document.createElement('div');
    header.textContent = 'Python equivalent:';
    header.style.cssText = `
        background: #28a745;
        color: white;
        padding: 8px;
        font-weight: bold;
        font-size: 14px;
    `;
    
    const codeBlock = document.createElement('pre');
    codeBlock.textContent = pythonCode;
    codeBlock.style.cssText = `
        margin: 0;
        padding: 15px;
        background: #f8fff8;
        overflow-x: auto;
    `;
    
    convertedDiv.appendChild(header);
    convertedDiv.appendChild(codeBlock);
    example.appendChild(convertedDiv);
}

function addStatusBadges() {
    // Add status badges to features
    const badges = {
        '✅ Active': 'status-active',
        '🚧 Planned': 'status-planned',
        '🧪 Experimental': 'status-experimental'
    };
    
    Object.keys(badges).forEach(function(text) {
        const elements = document.querySelectorAll('*');
        elements.forEach(function(element) {
            if (element.textContent && element.textContent.includes(text) && !element.querySelector('.status-badge')) {
                const badge = document.createElement('span');
                badge.className = 'status-badge ' + badges[text];
                badge.textContent = text;
                
                // Replace the text with the badge
                element.innerHTML = element.innerHTML.replace(text, badge.outerHTML);
            }
        });
    });
}

/**
 * Enhance navigation with proper memory management
 */
function enhanceNavigation() {
    // Add smooth scrolling to anchor links
    const anchors = document.querySelectorAll('a[href^="#"]');
    
    anchors.forEach(function(anchor) {
        const clickHandler = function(e) {
            e.preventDefault();
            
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        };
        
        // Register event listener with cleanup tracking
        MemoryManager.addEventListener(anchor, 'click', clickHandler);
    });
    
    // Add table of contents highlighting
    highlightCurrentSection();
}

/**
 * Highlight current section in table of contents with proper memory management
 */
function highlightCurrentSection() {
    const sections = document.querySelectorAll('h1[id], h2[id], h3[id]');
    const tocLinks = document.querySelectorAll('.wy-menu a');
    
    function updateHighlight() {
        let currentSection = null;
        
        sections.forEach(function(section) {
            const rect = section.getBoundingClientRect();
            if (rect.top <= 100) {
                currentSection = section;
            }
        });
        
        // Remove existing highlights
        tocLinks.forEach(function(link) {
            link.classList.remove('current-section');
        });
        
        // Add highlight to current section
        if (currentSection) {
            const currentLink = document.querySelector(`.wy-menu a[href="#${currentSection.id}"]`);
            if (currentLink) {
                currentLink.classList.add('current-section');
                currentLink.style.background = '#e3f2fd';
                currentLink.style.borderLeft = '3px solid #2196f3';
            }
        }
    }
    
    // Register scroll event listener with cleanup tracking
    MemoryManager.addEventListener(window, 'scroll', updateHighlight);
    updateHighlight(); // Initial call
}

// Add keyboard shortcuts with proper memory management
const keyboardHandler = function(e) {
    // Ctrl/Cmd + K to focus search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const search = document.querySelector('[name="q"]');
        if (search) {
            search.focus();
        }
    }
    
    // Escape to close any open modals or panels
    if (e.key === 'Escape') {
        const convertedCodes = document.querySelectorAll('.converted-code');
        convertedCodes.forEach(function(code) {
            code.remove();
        });
    }
};

// Register keyboard event listener with cleanup tracking
MemoryManager.addEventListener(document, 'keydown', keyboardHandler);

// Add API endpoint testing functionality
/**
 * Add API testing functionality with proper memory management
 */
function addAPITester() {
    const endpoints = document.querySelectorAll('.api-endpoint');
    
    endpoints.forEach(function(endpoint) {
        const testButton = document.createElement('button');
        testButton.textContent = 'Test API';
        testButton.className = 'test-api-button';
        testButton.style.cssText = `
            margin: 10px 0;
            padding: 8px 16px;
            background: #17a2b8;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        `;
        
        endpoint.appendChild(testButton);
        
        const clickHandler = function() {
            // This would open a testing interface
            console.log('API testing interface would open here');
        };
        
        // Register event listener with cleanup tracking
        MemoryManager.addEventListener(testButton, 'click', clickHandler);
    });
}

// Initialize API tester when page loads
document.addEventListener('DOMContentLoaded', addAPITester);