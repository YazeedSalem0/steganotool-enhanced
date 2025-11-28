$(document).ready(function() {
    // Set up AJAX to always include the auth token in request headers if available
    $.ajaxSetup({
        beforeSend: function(xhr) {
            const token = localStorage.getItem('auth_token');
            if (token) {
                xhr.setRequestHeader('Authorization', 'Bearer ' + token);
            }
        }
    });
    
    // Handle 401 Unauthorized responses globally
    $(document).ajaxError(function(event, jqXHR, settings, thrownError) {
        if (jqXHR.status === 401) {
            // Store the current URL to redirect back after login
            localStorage.setItem('redirect_after_login', window.location.href);
            
            // Redirect to sign-in page
            window.location.href = '/sign-in';
        }
    });
    
    // Animation for page elements on load
    setTimeout(function() {
        $(".hero-title, .hero-subtitle, .hero-buttons, .hero-image").addClass("animate-in");
    }, 100);
    
    setTimeout(function() {
        $(".feature-card").each(function(index) {
            var delay = 100 * index;
            var card = $(this);
            setTimeout(function() {
                card.addClass("animate-in");
            }, delay);
        });
    }, 600);
    
    // Tab switching functionality
    $(".tab-btn").click(function() {
        const tabId = $(this).data("tab");
        
        // Update active tab button
        $(".tab-btn").removeClass("active");
        $(this).addClass("active");
        
        // Show the selected tab content
        $(".tab-pane").removeClass("active");
        $("#" + tabId).addClass("active");
        
        // Update workflow animations based on active tab
        if (typeof onTabSwitch === 'function') {
            onTabSwitch();
        }
    });
    
    // Initialize workflow tabs for the initial active tab
    setTimeout(function() {
        if (typeof onTabSwitch === 'function') {
            onTabSwitch();
        }
    }, 800);
    
    // Media type selection
    $(".toggle-option input[type='radio']").change(function() {
        const parentGroup = $(this).closest(".media-selector");
        parentGroup.find(".toggle-option").removeClass("active");
        $(this).closest(".toggle-option").addClass("active");
        
        // Update file icon based on media type
        const fileDropArea = $(this).closest("form").find(".file-drop-area");
        const mediaType = $(this).val();
        
        if (mediaType === "image") {
            fileDropArea.find(".file-icon i").attr("class", "bi bi-file-earmark-image");
            // Hide QR specific options and show standard file area
            $(this).closest("form").find(".qr-specific-options").hide();
            $(this).closest("form").find("#standard-file-area").show();
        } else if (mediaType === "audio") {
            fileDropArea.find(".file-icon i").attr("class", "bi bi-file-earmark-music");
            // Hide QR specific options and show standard file area
            $(this).closest("form").find(".qr-specific-options").hide();
            $(this).closest("form").find("#standard-file-area").show();
        } else if (mediaType === "qr_code") {
            fileDropArea.find(".file-icon i").attr("class", "bi bi-qr-code");
            // Show QR specific options and hide standard file area
            $(this).closest("form").find(".qr-specific-options").show();
            $(this).closest("form").find("#standard-file-area").hide();
        }
    });
    
    // File Drop Area functionality
    $(".file-drop-area").each(function() {
        const dropArea = $(this);
        const inputFile = dropArea.find("input[type='file']");
        
        // Highlight drop area when file is dragged over
        ['dragenter', 'dragover'].forEach(eventName => {
            dropArea[0].addEventListener(eventName, highlight, false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            dropArea[0].addEventListener(eventName, unhighlight, false);
        });
        
        // Prevent default behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropArea[0].addEventListener(eventName, preventDefaults, false);
        });
        
        // Handle dropped files
        dropArea[0].addEventListener('drop', handleDrop, false);
        
        // Handle file selection
        inputFile.on('change', function() {
            handleFiles(this.files);
        });
        
        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }
        
        function highlight() {
            dropArea.addClass('highlight');
        }
        
        function unhighlight() {
            dropArea.removeClass('highlight');
        }
        
        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            inputFile[0].files = files;
            handleFiles(files);
        }
        
        function handleFiles(files) {
            if (files.length === 0) return;
            
            const fileName = files[0].name;
            const fileIcon = dropArea.find(".file-icon i");
            const fileMessage = dropArea.find(".file-message .main-text");
            
            // Update the UI to show the selected file
            fileMessage.text(fileName);
            
            // Adjust icon based on file type
            if (files[0].type.startsWith("image/")) {
                fileIcon.attr("class", "bi bi-file-earmark-image");
            } else if (files[0].type.startsWith("audio/")) {
                fileIcon.attr("class", "bi bi-file-earmark-music");
            } else {
                fileIcon.attr("class", "bi bi-file-earmark");
            }
            
            // Update file info
            dropArea.addClass("has-file");
        }
    });
    
    // Toggle password field based on auto-generate checkbox
    $("#autoGeneratePassword").change(function() {
        if($(this).is(":checked")) {
            $("#encryptPassword").prop("required", false);
            $("#passwordInputGroup").addClass("muted-field");
        } else {
            $("#encryptPassword").prop("required", true);
            $("#passwordInputGroup").removeClass("muted-field");
        }
    });

    // Encrypt form submission
    $("#encryptForm").submit(function(e) {
        e.preventDefault();
        
        // Show loading state
        const btn = $(this).find('button[type="submit"]');
        const originalBtnText = btn.html();
        btn.html('<div class="loading"><div></div><div></div><div></div></div> Processing...');
        btn.prop('disabled', true);
        
        // Get selected media type
        const mediaType = $(this).find('input[name="media_type"]:checked').val();
        
        // Validate form manually when auto-generate is not checked
        if (!$("#autoGeneratePassword").is(":checked") && !$("#encryptPassword").val()) {
            showMessage("#encryptionResult", "error", "Please provide a password or enable auto-generate option.");
            btn.html(originalBtnText);
            btn.prop('disabled', false);
            return;
        }

        var formData = new FormData(this);
        
        // Use different API endpoint based on media type
        let apiEndpoint = '/api/encrypt';
        if (mediaType === "qr_code") {
            apiEndpoint = '/api/encrypt-qr';
        }
        
        $.ajax({
            url: apiEndpoint,
            type: 'POST',
            data: formData,
            contentType: false,
            processData: false,
            success: function(response) {
                btn.html(originalBtnText);
                btn.prop('disabled', false);
                
                if (response.status === 'success') {
                    let resultContent = `
                        <div class="alert alert-success animate-fade-in">
                            <h4 class="alert-heading"><i class="bi bi-check-circle"></i> Success!</h4>
                            <p>Your message has been encrypted and hidden successfully.</p>
                            <hr>
                            <div class="result-details">
                                <p><strong><i class="bi bi-file-earmark"></i> Output File:</strong> ${response.output_filename}</p>
                    `;
                    
                    // Add encryption method information
                    let encryptionMethod = response.encryption_method || "AES-256";
                    let mediaTypeDisplay = response.hiding_technique || "";
                    
                    if (!mediaTypeDisplay) {
                        if (mediaType === "image" || response.media_type === "image") {
                            mediaTypeDisplay = "LSB Image Steganography";
                        } else if (mediaType === "audio" || response.media_type === "audio") {
                            mediaTypeDisplay = "Audio Sample Steganography";
                        } else if (mediaType === "qr_code" || response.media_type === "qr_code") {
                            mediaTypeDisplay = "QR Code Steganography";
                        }
                    }
                    
                    resultContent += `
                        <div class="encryption-info">
                            <p><strong><i class="bi bi-shield-lock"></i> Encryption Method:</strong> ${encryptionMethod}</p>
                            <p><strong><i class="bi bi-layers"></i> Hiding Technique:</strong> ${mediaTypeDisplay}</p>
                    `;
                    
                    // Add compression info if available
                    if (response.compression_ratio) {
                        resultContent += `
                            <p><strong><i class="bi bi-file-zip"></i> Compression:</strong> ${Math.round(response.compression_ratio)}% reduction in size</p>
                        `;
                    }
                    
                    resultContent += `</div>`;
                    
                    if (response.auto_generated_password) {
                        resultContent += `
                            <div class="password-box">
                                <div class="d-flex justify-content-between align-items-center">
                                    <p class="mb-0"><strong><i class="bi bi-key"></i> Auto-Generated Password:</strong></p>
                                    <button class="btn btn-sm copy-btn" data-clipboard="${response.auto_generated_password}">
                                        <i class="bi bi-clipboard"></i> Copy
                                    </button>
                                </div>
                                <p class="password-value">${response.auto_generated_password}</p>
                                <p class="text-warning mb-0"><small><i class="bi bi-info-circle"></i> This password is stored in the file and will be extracted automatically during decryption.</small></p>
                            </div>
                        `;
                    }
                    
                    // Add QR code preview if it's a QR code
                    if (mediaType === "qr_code" || response.media_type === "qr_code") {
                        resultContent += `
                            <div class="qr-preview-box mt-3">
                                <h5><i class="bi bi-qr-code"></i> QR Code Preview</h5>
                                <img src="/api/download/${response.output_filename}" class="img-fluid qr-preview-image" style="max-width: 200px;">
                                <p class="mt-2"><small>Style: ${response.style || 'Standard'}</small></p>
                            </div>
                        `;
                    }
                    
                    resultContent += `
                                <div class="mt-3">
                                    <a href="/api/download/${response.output_filename}" class="btn btn-primary">
                                        <i class="bi bi-download"></i> Download File
                                    </a>
                                </div>
                            </div>
                        </div>
                    `;
                    
                    showMessage("#encryptionResult", "custom", resultContent);
                    
                    // Reset the form UI for next use
                    resetFormUI($("#encryptForm"));
                } else {
                    showMessage("#encryptionResult", "error", response.message || "An error occurred");
                }
            },
            error: function(xhr) {
                btn.html(originalBtnText);
                btn.prop('disabled', false);
                
                let errorMsg = "An error occurred during encryption";
                try {
                    const response = JSON.parse(xhr.responseText);
                    errorMsg = response.message || errorMsg;
                } catch (e) {}
                
                showMessage("#encryptionResult", "error", errorMsg);
            }
        });
    });

    // Decrypt form submission
    $("#decryptForm").submit(function(e) {
        e.preventDefault();
        
        // Show loading state
        const btn = $(this).find('button[type="submit"]');
        const originalBtnText = btn.html();
        btn.html('<div class="loading"><div></div><div></div><div></div></div> Processing...');
        btn.prop('disabled', true);
        
        // Get selected media type
        const mediaType = $(this).find('input[name="media_type"]:checked').val();
        
        var formData = new FormData(this);
        
        // Use different API endpoint based on media type
        let apiEndpoint = '/api/decrypt';
        if (mediaType === "qr_code") {
            apiEndpoint = '/api/decrypt-qr';
        }
        
        $.ajax({
            url: apiEndpoint,
            type: 'POST',
            data: formData,
            contentType: false,
            processData: false,
            success: function(response) {
                btn.html(originalBtnText);
                btn.prop('disabled', false);
                
                if (response.status === 'success' || response.status === 'warning') {
                    let alertClass = response.status === 'warning' ? 'alert-warning' : 'alert-success';
                    let resultContent = `
                        <div class="alert ${alertClass} animate-fade-in">
                            <h4 class="alert-heading">
                                <i class="${response.status === 'warning' ? 'bi bi-exclamation-triangle' : 'bi bi-check-circle'}"></i> 
                                ${response.status === 'warning' ? 'Warning' : 'Success'}!
                            </h4>
                    `;
                    
                    if (response.status === 'warning') {
                        resultContent += `<p>The message was extracted, but there may be issues with the content.</p>`;
                    } else {
                        resultContent += `<p>Hidden message successfully extracted and decrypted.</p>`;
                    }
                    
                    resultContent += `<hr>`;
                    
                    // Add encryption method information if available
                    let encryptionMethod = response.encryption_method || "AES-256";
                    let mediaTypeDisplay = response.hiding_technique || "";
                    
                    if (!mediaTypeDisplay) {
                        if (mediaType === "image" || response.media_type === "image") {
                            mediaTypeDisplay = "LSB Image Steganography";
                        } else if (mediaType === "audio" || response.media_type === "audio") {
                            mediaTypeDisplay = "Audio Sample Steganography";
                        } else if (mediaType === "qr_code" || response.media_type === "qr_code") {
                            mediaTypeDisplay = "QR Code Steganography";
                        }
                    }
                    
                    resultContent += `
                        <div class="encryption-info">
                            <p><strong><i class="bi bi-shield-lock"></i> Encryption Method:</strong> ${encryptionMethod}</p>
                            <p><strong><i class="bi bi-layers"></i> Extraction Technique:</strong> ${mediaTypeDisplay}</p>
                        </div>
                    `;
                    
                    // Show if password was auto-extracted
                    if (response.password_found) {
                        resultContent += `
                            <div class="mb-3">
                                <p class="text-success"><i class="bi bi-key"></i> <strong>Password was automatically extracted from the file.</strong></p>
                            </div>
                        `;
                    }
                    
                    // Display the message
                    resultContent += `
                        <div class="message-box">
                            <h5><i class="bi bi-chat-square-text"></i> Extracted Message:</h5>
                            <div class="message-content">${response.message}</div>
                            <button class="btn btn-sm copy-btn mt-2" data-clipboard="${response.message}">
                                <i class="bi bi-clipboard"></i> Copy Message
                            </button>
                        </div>
                    </div>
                    `;
                    
                    $(decryptionResult).html(resultContent);
                    
                    // Initialize copy buttons
                    $(".copy-btn").click(function() {
                        const textToCopy = $(this).attr('data-clipboard');
                        copyToClipboard(textToCopy);
                        
                        // Show copied animation
                        const originalText = $(this).html();
                        $(this).html('<i class="bi bi-check"></i> Copied!');
                        setTimeout(() => {
                            $(this).html(originalText);
                        }, 2000);
                    });
                } else {
                    showMessage("#decryptionResult", "error", response.message || "Failed to decrypt the file. Please check your password and try again.");
                }
            },
            error: function(xhr, status, error) {
                btn.html(originalBtnText);
                btn.prop('disabled', false);
                
                let errorMsg = "Error occurred while decrypting.";
                try {
                    const response = JSON.parse(xhr.responseText);
                    errorMsg = response.message || response.error || errorMsg;
                } catch (e) {
                    console.error("Error parsing error response:", e);
                }
                
                showMessage("#decryptionResult", "error", errorMsg);
            }
        });
    });
    
    // Function to reset form UI after submission
    function resetFormUI(form) {
        // Reset file drop area
        const dropArea = form.find(".file-drop-area");
        const fileIcon = dropArea.find(".file-icon i");
        const fileMessage = dropArea.find(".file-message .main-text");
        
        // Reset based on media type
        const mediaType = form.find("input[name='media_type']:checked").val();
        if (mediaType === "image") {
            fileIcon.attr("class", "bi bi-file-earmark-image");
        } else {
            fileIcon.attr("class", "bi bi-file-earmark-music");
        }
        
        fileMessage.text("Drop your file here");
        dropArea.removeClass("has-file highlight");
        
        // Reset text inputs but not select/radio/checkbox
        form.find('input[type="text"], input[type="password"], textarea').val('');
    }
    
    // Handle copy button clicks
    $(document).on('click', '.copy-btn', function() {
        const textToCopy = $(this).data('clipboard');
        navigator.clipboard.writeText(textToCopy).then(() => {
            const originalText = $(this).html();
            $(this).html('<i class="bi bi-check"></i> Copied!');
            setTimeout(() => {
                $(this).html(originalText);
            }, 2000);
        });
    });

    // Function to display messages
    function showMessage(selector, type, message) {
        const element = $(selector);
        element.empty();
        
        if (type === "custom") {
            element.html(message);
        } else if (type === "error") {
            element.html(`
                <div class="alert alert-danger animate-fade-in">
                    <h4 class="alert-heading">
                        <i class="bi bi-exclamation-triangle"></i> Error
                    </h4>
                    <p>${message}</p>
                </div>
            `);
        } else if (type === "success") {
            element.html(`
                <div class="alert alert-success animate-fade-in">
                    <h4 class="alert-heading">
                        <i class="bi bi-check-circle"></i> Success
                    </h4>
                    <p>${message}</p>
                </div>
            `);
        }
        
        // Scroll to the message
        $('html, body').animate({
            scrollTop: element.offset().top - 100
        }, 500);
    }
    
    // Smooth scroll for anchor links
    $('a[href^="#"]').on('click', function(e) {
        e.preventDefault();
        
        const target = $(this.hash);
        if (target.length) {
            $('html, body').animate({
                scrollTop: target.offset().top - 70
            }, 500);
        }
    });

    // URL Scanner form submission
    $("#urlScanForm").submit(function(e) {
        e.preventDefault();
        
        const url = $("#urlToScan").val().trim();
        if (!url) {
            showMessage("#urlScanResult", "error", "Please enter a URL to scan");
            return;
        }
        
        // Show loading state
        const btn = $(this).find('button[type="submit"]');
        const originalBtnText = btn.html();
        btn.html('<div class="loading"><div></div><div></div><div></div></div> Scanning...');
        btn.prop('disabled', true);
        
        // Send scan request
        $.ajax({
            url: '/api/scan-url',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ url: url }),
            success: function(response) {
                btn.html(originalBtnText);
                btn.prop('disabled', false);
                
                if (response.status === 'success') {
                    // Show initial success message
                    let resultContent = `
                        <div class="alert alert-info animate-fade-in">
                            <h4 class="alert-heading"><i class="bi bi-check-circle"></i> URL Submitted for Scanning</h4>
                            <p>Your URL has been submitted to VirusTotal for analysis.</p>
                            <hr>
                            <p><strong>Analysis ID:</strong> <code>${response.analysis_id}</code></p>
                            <p class="mb-0">Please wait while we retrieve the scan results...</p>
                        </div>
                    `;
                    showMessage("#urlScanResult", "custom", resultContent);
                    
                    // Poll for analysis results
                    pollAnalysisResults(response.analysis_id, url);
                } else {
                    showMessage("#urlScanResult", "error", response.message || "Failed to scan URL");
                }
            },
            error: function(xhr) {
                btn.html(originalBtnText);
                btn.prop('disabled', false);
                
                let errorMsg = "An error occurred while scanning the URL";
                try {
                    const response = JSON.parse(xhr.responseText);
                    errorMsg = response.message || errorMsg;
                } catch (e) {}
                
                showMessage("#urlScanResult", "error", errorMsg);
            }
        });
    });
    
    // Function to poll for analysis results
    function pollAnalysisResults(analysisId, url, attempts = 0) {
        const maxAttempts = 30; // Maximum polling attempts (increased from 10)
        const pollInterval = 5000; // 5 seconds between polls (increased from 3)
        
        if (attempts >= maxAttempts) {
            showMessage("#urlScanResult", "error", "Timeout waiting for scan results. The scan may still be in progress. Please try again in a few minutes or check the analysis ID manually.");
            return;
        }
        
        // Update status message to show progress
        if (attempts > 0) {
            const progressMsg = `
                <div class="alert alert-info animate-fade-in">
                    <h4 class="alert-heading"><i class="bi bi-hourglass-split"></i> Scan in Progress</h4>
                    <p>Waiting for VirusTotal to complete the scan... (Attempt ${attempts}/${maxAttempts})</p>
                    <p><strong>Analysis ID:</strong> <code>${analysisId}</code></p>
                    <p class="mb-0"><small>This may take up to 2-3 minutes. Please wait...</small></p>
                </div>
            `;
            $("#urlScanResult").html(progressMsg);
        }
        
        setTimeout(function() {
            $.ajax({
                url: `/api/url-analysis/${analysisId}`,
                type: 'GET',
                success: function(response) {
                    if (response.status === 'success') {
                        const status = response.status_analysis;
                        
                        // Check if scan is completed
                        if (status === 'completed') {
                            // Display results
                            displayScanResults(response, url);
                        } else if (status === 'queued' || status === 'in-progress' || status === 'in_progress') {
                            // Still processing, poll again
                            pollAnalysisResults(analysisId, url, attempts + 1);
                        } else {
                            // Unknown status, but might have stats anyway
                            if (response.total_scans > 0) {
                                displayScanResults(response, url);
                            } else {
                                // Continue polling if no stats yet
                                pollAnalysisResults(analysisId, url, attempts + 1);
                            }
                        }
                    } else {
                        showMessage("#urlScanResult", "error", response.message || "Failed to retrieve scan results");
                    }
                },
                error: function(xhr) {
                    // If 404 or other error, might still be processing
                    if ((xhr.status === 404 || xhr.status === 429) && attempts < maxAttempts) {
                        pollAnalysisResults(analysisId, url, attempts + 1);
                    } else {
                        let errorMsg = "Failed to retrieve scan results";
                        try {
                            const response = JSON.parse(xhr.responseText);
                            errorMsg = response.message || errorMsg;
                        } catch (e) {}
                        showMessage("#urlScanResult", "error", errorMsg);
                    }
                }
            });
        }, pollInterval);
    }
    
    // Function to display scan results
    function displayScanResults(data, url) {
        const totalScans = data.total_scans || 0;
        const malicious = data.malicious || 0;
        const suspicious = data.suspicious || 0;
        const harmless = data.harmless || 0;
        const undetected = data.undetected || 0;
        
        // Determine threat level
        let threatLevel = "safe";
        let alertClass = "alert-success";
        let threatIcon = "bi-shield-check";
        let threatText = "Safe";
        
        if (malicious > 0) {
            threatLevel = "malicious";
            alertClass = "alert-danger";
            threatIcon = "bi-shield-x";
            threatText = "Malicious";
        } else if (suspicious > 0) {
            threatLevel = "suspicious";
            alertClass = "alert-warning";
            threatIcon = "bi-shield-exclamation";
            threatText = "Suspicious";
        }
        
        let resultContent = `
            <div class="alert ${alertClass} animate-fade-in">
                <h4 class="alert-heading">
                    <i class="bi ${threatIcon}"></i> Scan Results: ${threatText}
                </h4>
                <p><strong>URL:</strong> <code>${url}</code></p>
                <hr>
                <div class="scan-stats">
                    <h5><i class="bi bi-bar-chart"></i> Scan Statistics</h5>
                    <div class="row mt-3">
                        <div class="col-md-6">
                            <div class="stat-item ${malicious > 0 ? 'text-danger' : ''}">
                                <i class="bi bi-x-circle"></i> <strong>Malicious:</strong> ${malicious}
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="stat-item ${suspicious > 0 ? 'text-warning' : ''}">
                                <i class="bi bi-exclamation-triangle"></i> <strong>Suspicious:</strong> ${suspicious}
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="stat-item text-success">
                                <i class="bi bi-check-circle"></i> <strong>Harmless:</strong> ${harmless}
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="stat-item text-muted">
                                <i class="bi bi-question-circle"></i> <strong>Undetected:</strong> ${undetected}
                            </div>
                        </div>
                    </div>
                    <div class="mt-3">
                        <p><strong>Total Scans:</strong> ${totalScans}</p>
                        ${data.scan_date ? `<p><strong>Scan Date:</strong> ${new Date(data.scan_date * 1000).toLocaleString()}</p>` : ''}
                    </div>
                </div>
                ${malicious > 0 || suspicious > 0 ? `
                    <div class="mt-3">
                        <div class="alert alert-warning">
                            <strong><i class="bi bi-exclamation-triangle"></i> Warning:</strong> 
                            This URL has been flagged by ${malicious + suspicious} security engine(s). 
                            Exercise caution when visiting this URL.
                        </div>
                    </div>
                ` : ''}
                ${harmless > 0 && malicious === 0 && suspicious === 0 ? `
                    <div class="mt-3">
                        <div class="alert alert-success">
                            <strong><i class="bi bi-check-circle"></i> Safe:</strong> 
                            This URL appears to be safe based on VirusTotal's analysis.
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
        
        showMessage("#urlScanResult", "custom", resultContent);
        
        // Scroll to results
        $('html, body').animate({
            scrollTop: $("#urlScanResult").offset().top - 100
        }, 500);
    }
}); 