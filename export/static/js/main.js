// static/js/main.js

/**
 * AIRecruiter Pro - Main JavaScript
 * Modern UI interactions and form handlers
 */

document.addEventListener('DOMContentLoaded', function() {
    initializeTooltips();
    initializeModals();
    initializeDropdowns();
    setupFlashMessages();
    setupFormHandlers();
    setupHtmxIntegration();
    setupDragAndDropUploads();
});

// ====================
// UI Component Handlers
// ====================

function initializeTooltips() {
    const tooltips = document.querySelectorAll('[data-tooltip]');
    
    tooltips.forEach(tooltip => {
        tooltip.addEventListener('mouseenter', function() {
            const text = this.getAttribute('data-tooltip');
            const tooltipEl = document.createElement('div');
            tooltipEl.className = 'tooltip';
            tooltipEl.textContent = text;
            document.body.appendChild(tooltipEl);
            
            const rect = this.getBoundingClientRect();
            tooltipEl.style.top = `${rect.top - tooltipEl.offsetHeight - 10}px`;
            tooltipEl.style.left = `${rect.left + (rect.width / 2) - (tooltipEl.offsetWidth / 2)}px`;
            tooltipEl.style.opacity = '1';
        });
        
        tooltip.addEventListener('mouseleave', function() {
            const tooltipEl = document.querySelector('.tooltip');
            if (tooltipEl) {
                tooltipEl.style.opacity = '0';
                setTimeout(() => tooltipEl.remove(), 300);
            }
        });
    });
}

function initializeModals() {
    const modals = document.querySelectorAll('.modal');
    
    modals.forEach(modal => {
        // Close modal when clicking outside content
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                hideModal(modal.id);
            }
        });
    });
    
    // Job form modal handlers
    window.showJobForm = function() {
        const jobForm = document.getElementById('jobForm');
        if (jobForm) {
            jobForm.style.display = 'flex';
            setTimeout(() => {
                jobForm.querySelector('.modal-content').style.opacity = '1';
                jobForm.querySelector('.modal-content').style.transform = 'translateY(0)';
            }, 10);
            document.body.style.overflow = 'hidden';
        }
    };
    
    window.hideJobForm = function() {
        hideModal('jobForm');
    };
}

function hideModal(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    
    const content = modal.querySelector('.modal-content');
    content.style.opacity = '0';
    content.style.transform = 'translateY(20px)';
    
    setTimeout(() => {
        modal.style.display = 'none';
        document.body.style.overflow = '';
        
        // Reset form and messages if present
        const form = modal.querySelector('form');
        if (form) form.reset();
        
        const messageContainer = modal.querySelector('[id$="Message"]');
        if (messageContainer) messageContainer.innerHTML = '';
    }, 300);
}

function initializeDropdowns() {
    const dropdownToggle = document.querySelectorAll('.dropdown-toggle');
    
    dropdownToggle.forEach(toggle => {
        toggle.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            const dropdown = this.nextElementSibling;
            dropdown.classList.toggle('show');
        });
    });
    
    // Close dropdowns when clicking outside
    document.addEventListener('click', function() {
        const openDropdowns = document.querySelectorAll('.dropdown-menu.show');
        openDropdowns.forEach(dropdown => {
            dropdown.classList.remove('show');
        });
    });
}

function setupFlashMessages() {
    setTimeout(() => {
        const messages = document.querySelectorAll('.flash-message, .alert');
        messages.forEach(msg => {
            msg.style.opacity = '0';
            setTimeout(() => msg.remove(), 300);
        });
    }, 5000);
}

// ====================
// Form Handlers
// ====================

function setupFormHandlers() {
    setupJobForm();
    setupResumeUploadForm();
    setupBulkUploadForm();
}

function setupJobForm() {
    const jobCreationForm = document.getElementById('jobCreationForm');
    if (!jobCreationForm) return;
    
    jobCreationForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const messageContainer = document.getElementById('jobMessage');
        const submitBtn = this.querySelector('button[type="submit"]');
        const jobDescription = document.getElementById('jobDescription').value;
        const jobLocation = document.getElementById('jobLocation')?.value || "";
        const jobExperience = document.getElementById('jobExperience')?.value || "";
        
        if (!jobDescription) {
            showMessage(messageContainer, 'error', 'Job description is required.');
            return;
        }
        
        // Show loading state
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="material-icons spin">refresh</i> Processing...';
        }
        
        showMessage(messageContainer, 'info', 'Analyzing job description with AI. This might take a moment...', true);
        
        // Prepare the request payload with optional fields
        const payload = { 
            description: jobDescription 
        };
        
        // Add optional fields only if they have values
        if (jobLocation.trim()) {
            payload.location = jobLocation.trim();
        }
        if (jobExperience.trim()) {
            payload.experience = jobExperience.trim();
        }
        
        try {
            const response = await fetch('/api/jobs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Build success message with job details
                let successMessage = `Job created successfully!<br>
                    <strong>Title:</strong> ${data.title}<br>`;
                
                // Add location and experience to success message if they exist
                if (data.location) {
                    successMessage += `<strong>Location:</strong> ${data.location}<br>`;
                }
                if (data.experience) {
                    successMessage += `<strong>Experience:</strong> ${data.experience}<br>`;
                }
                
                successMessage += `<strong>Required Skills:</strong> ${Array.isArray(data.required_skills) ? data.required_skills.join(', ') : 'None specified'}<br>
                    Refreshing page...`;
                
                showMessage(messageContainer, 'success', successMessage, true);
                
                setTimeout(() => {
                    hideJobForm();
                    window.location.reload();
                }, 2000);
            } else {
                showMessage(messageContainer, 'error', data.error || 'An unexpected error occurred.');
                
                // Reset button
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = '<i class="material-icons">auto_awesome</i> Analyze & Create';
                }
            }
        } catch (error) {
            showMessage(messageContainer, 'error', `Network error: ${error.message}. Please try again.`);
            
            // Reset button
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="material-icons">auto_awesome</i> Analyze & Create';
            }
        }
    });
}

function setupResumeUploadForm() {
    const resumeUploadForm = document.getElementById('resumeUploadForm');
    if (!resumeUploadForm) return;
    
    resumeUploadForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const messageContainer = document.getElementById('uploadMessage');
        const submitBtn = this.querySelector('button[type="submit"]');
        const formData = new FormData(resumeUploadForm);
        
        // Show loading state
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="material-icons spin">refresh</i> Uploading...';
        }
        
        showMessage(messageContainer, 'info', 'Uploading and analyzing resume...', true);
        
        try {
            const response = await fetch('/api/candidates', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (response.ok) {
                showMessage(messageContainer, 'success', data.message || 'Resume uploaded successfully!');
                resumeUploadForm.reset();
                
                const fileNameDisplay = resumeUploadForm.querySelector('.file-name');
                if (fileNameDisplay) {
                    fileNameDisplay.textContent = 'No file selected';
                }
            } else {
                showMessage(messageContainer, 'error', data.error || 'Failed to upload resume.');
            }
        } catch (error) {
            showMessage(messageContainer, 'error', `Network error: ${error.message}`);
        } finally {
            // Reset button
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = 'Upload Resume';
            }
        }
    });
}

function setupBulkUploadForm() {
    // Handle bulk upload progress and UI (this is bound to the event handlers in dashboard.html)
    // The actual implementation is in the dashboard template
}

// ====================
// Utility Functions
// ====================

function showMessage(container, type, message, isHTML = false) {
    if (!container) return;
    
    let iconName = 'info';
    let bgColor = '#e0f2fe';
    let iconBgColor = '#0284c7';
    let textColor = '#0369a1';
    
    switch (type) {
        case 'success':
            iconName = 'check_circle';
            bgColor = '#d1fae5';
            iconBgColor = '#065f46';
            textColor = '#065f46';
            break;
        case 'error':
            iconName = 'error';
            bgColor = '#fee2e2';
            iconBgColor = '#b91c1c';
            textColor = '#b91c1c';
            break;
        case 'warning':
            iconName = 'warning';
            bgColor = '#fef3c7';
            iconBgColor = '#92400e';
            textColor = '#92400e';
            break;
    }
    
    const messageHTML = `
        <div class="info-box" style="background-color: ${bgColor};">
            <div class="info-icon" style="background-color: ${iconBgColor};">
                <i class="material-icons">${iconName}</i>
            </div>
            <p style="color: ${textColor};">
                ${isHTML ? message : escapeHTML(message)}
            </p>
        </div>
    `;
    
    container.innerHTML = messageHTML;
}

function escapeHTML(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// ====================
// HTMX Integration
// ====================

function setupHtmxIntegration() {
    document.body.addEventListener('htmx:afterRequest', function(evt) {
        if (evt.detail.target && evt.detail.target.id === 'candidatesContainer' && evt.detail.successful) {
            document.getElementById('candidatesContainer').scrollIntoView({ behavior: 'smooth' });
        }
    });
}

// ====================
// File Upload Enhancements
// ====================

function setupDragAndDropUploads() {
    // Set up simple file input display
    const fileInputs = document.querySelectorAll('.file-input');
    
    fileInputs.forEach(input => {
        input.addEventListener('change', function(e) {
            const fileName = e.target.files[0] ? e.target.files[0].name : 'No file selected';
            const fileNameElement = this.parentElement.querySelector('.file-name');
            if (fileNameElement) {
                fileNameElement.textContent = fileName;
            }
        });
    });
    
    // Setup drag and drop zones (the event handlers are in dashboard.html)
    const dropZones = document.querySelectorAll('.upload-zone-modern');
    dropZones.forEach(zone => {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            zone.addEventListener(eventName, preventDefaults, false);
        });
        
        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }
        
        // Highlight effect
        ['dragenter', 'dragover'].forEach(eventName => {
            zone.addEventListener(eventName, () => {
                zone.classList.add('highlight');
            }, false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            zone.addEventListener(eventName, () => {
                zone.classList.remove('highlight');
            }, false);
        });
    });
}
