document.addEventListener('DOMContentLoaded', function() {
    // Close flash messages when clicked
    document.querySelectorAll('.flash').forEach(flash => {
        flash.addEventListener('click', () => {
            flash.style.display = 'none';
        });
    });

    // Auto-focus first input in forms
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        const firstInput = form.querySelector('input, select, textarea');
        if (firstInput) {
            firstInput.focus();
        }
    });

    // Tab switching for pay_rent.html
    const upiTab = document.getElementById('upi-tab');
    const manualTab = document.getElementById('manual-tab');
    const upiMethod = document.getElementById('upi-method');
    const manualMethod = document.getElementById('manual-method');

    function switchTab(activeTab, inactiveTab, activeMethod, inactiveMethod) {
        if (activeTab && inactiveTab && activeMethod && inactiveMethod) {
            activeTab.classList.add('active');
            inactiveTab.classList.remove('active');
            activeMethod.classList.add('active');
            inactiveMethod.classList.remove('active');
        }
    }

    if (upiTab && manualTab && upiMethod && manualMethod) {
        upiTab.addEventListener('click', function() {
            console.log('UPI Tab clicked'); // Added log
            switchTab(upiTab, manualTab, upiMethod, manualMethod);
        });

        manualTab.addEventListener('click', function() {
            console.log('Manual Tab clicked'); // Added log
            switchTab(manualTab, upiTab, manualMethod, upiMethod);
        });
    }

    // UPI payment flow for pay_rent.html
    const upiButton = document.getElementById('upi-pay-now');
    const modal = document.getElementById('confirmation-modal');
    const confirmBtn = document.getElementById('confirm-payment');
    const cancelBtn = document.getElementById('cancel-payment');
    const manualPaymentForm = document.querySelector('.manual-payment-form'); // Get the form

    if (upiButton) {
        upiButton.addEventListener('click', function(e) {
            e.preventDefault();
            console.log('UPI Pay Button clicked'); // Added log

            const originalText = upiButton.innerHTML;
            upiButton.disabled = true;
            upiButton.innerHTML = '<span>Opening UPI app...</span>';

            const upiLink = upiButton.dataset.upiLink;
            console.log('UPI Link:', upiLink);

            try {
                if (upiLink) {
                    window.open(upiLink, '_blank');
                } else {
                    throw new Error('UPI link not found');
                }

                setTimeout(() => {
                    if (modal && !document.hidden) {
                        modal.style.display = 'flex';
                        console.log('Modal display set to flex'); // Added log
                    }
                    upiButton.disabled = false;
                    upiButton.innerHTML = originalText;
                }, 3000);
            } catch (error) {
                console.error('Error opening UPI app:', error);
                alert('Failed to open UPI app. Please try again or use manual payment method.');
                upiButton.disabled = false;
                upiButton.innerHTML = originalText;
            }
        });
    }

    // Manual payment form submission logic
    if (manualPaymentForm) {
        manualPaymentForm.addEventListener('submit', function(e) {
            e.preventDefault(); // Prevent default form submission
            console.log('Manual Payment Form submitted'); // Added log

            // Show the confirmation modal
            if (modal) {
                modal.style.display = 'flex';
                console.log('Modal display set to flex (from manual form)'); // Added log
            }
        });
    }

    if (confirmBtn && modal) {
        confirmBtn.addEventListener('click', function() {
            const originalText = confirmBtn.innerHTML;
            confirmBtn.disabled = true;
            confirmBtn.innerHTML = 'Processing...';

            const csrfMeta = document.querySelector('meta[name="csrf-token"]');
            if (!csrfMeta) {
                console.error('CSRF token not found');
                alert('Security error. Please refresh the page and try again.');
                confirmBtn.disabled = false;
                confirmBtn.innerHTML = originalText;
                return;
            }
            const csrfToken = csrfMeta.content;

            // Submit the manual payment form
            if (manualPaymentForm) {
                // Create hidden input for confirmation flag and CSRF token
                const confirmInput = document.createElement('input');
                confirmInput.type = 'hidden';
                confirmInput.name = 'confirm_payment';
                confirmInput.value = 'true';
                manualPaymentForm.appendChild(confirmInput);

                const csrfInput = document.createElement('input');
                csrfInput.type = 'hidden';
                csrfInput.name = 'csrf_token';
                csrfInput.value = csrfToken;
                manualPaymentForm.appendChild(csrfInput);

                // Submit the form
                manualPaymentForm.submit();
            }
        });
    }

    if (cancelBtn && modal) {
        cancelBtn.addEventListener('click', function() {
            modal.style.display = 'none';
        });
    }

    if (modal) {
        modal.addEventListener('click', function(event) {
            if (event.target === modal) {
                modal.style.display = 'none';
            }
        });

        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape' && modal.style.display === 'flex') {
                modal.style.display = 'none';
            }
        });
    }
});

// Global function for WhatsApp messages
function sendWhatsAppMessage(phone, name) {
    const cleanedPhone = phone.replace(/\D/g, '');
    const message = `Hello ${name}, this is a message from duepae.`;
    const encodedMessage = encodeURIComponent(message);
    window.open(`https://wa.me/${cleanedPhone}?text=${encodedMessage}`, '_blank');
}

// JavaScript for payment_history.html
// Note: This part assumes jQuery is loaded. If not, it needs to be refactored to vanilla JS.
$(document).ready(function() {
    // Check if jsPDF and html2canvas are loaded
    if (typeof window.jsPDF !== 'undefined' && typeof html2canvas !== 'undefined') {
        window.jsPDF = window.jspdf.jsPDF; // Ensure jsPDF is correctly assigned

        // Handle receipt downloads
        $('.download-receipt').on('click', function(e) {
            e.preventDefault();
            const paymentId = $(this).data('payment-id');

            const btn = $(this);
            const originalHtml = btn.html();
            btn.html('<i class="fas fa-spinner fa-spin"></i> Generating...');
            btn.prop('disabled', true);

            $.get(`/download_receipt/${paymentId}`, function(data) {
                $('#receiptContent').html(data);
                $('#receiptModal').modal('show');
            })
            .fail(function() {
                alert('Failed to load receipt. Please try again.');
            })
            .always(function() {
                btn.html(originalHtml);
                btn.prop('disabled', false);
            });
        });

        // Print receipt
        $('#printReceipt').on('click', function() {
            window.print();
        });

        // Download receipt as PDF
        $('#downloadReceipt').on('click', function() {
            const element = document.getElementById('receiptContent');
            const filename = `Rent_Receipt_${new Date().toISOString().slice(0,10)}.pdf`;

            html2canvas(element, {
                scale: 2,
                useCORS: true,
                logging: false
            }).then(canvas => {
                const imgData = canvas.toDataURL('image/jpeg', 1.0);
                const pdf = new jsPDF({
                    orientation: 'portrait',
                    unit: 'mm',
                    format: 'a4'
                });

                const imgWidth = pdf.internal.pageSize.getWidth();
                const imgHeight = (canvas.height * imgWidth) / canvas.width;

                pdf.addImage(imgData, 'JPEG', 0, 0, imgWidth, imgHeight);
                pdf.save(filename);
            });
        });
    } else {
        console.warn("jsPDF or html2canvas not loaded. Receipt functionality may be limited.");
    }
});

// Global function for payment status modal (used by payment_history.html)
function showPaymentStatusModal(message, isSuccess) {
    const modal = document.createElement('div');
    modal.className = 'payment-status-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <h3>${isSuccess ? '✅ Success' : '⚠️ Notice'}</h3>
            <p>${message}</p>
            <button onclick="this.parentElement.parentElement.remove()">OK</button>
        </div>
    `;
    document.body.appendChild(modal);
}

// This part needs tenancyId and csrfToken from the template context
// It's better to pass these values from the Flask template to a global JS variable
// or data attributes on the relevant HTML elements.
// For example, in your Flask template:
// <script>
//     const GLOBAL_TENANCY_ID = {{ tenancy.id | tojson }};
//     const GLOBAL_CSRF_TOKEN = "{{ csrf_token() }}";
// </script>
// Then, in main.js, you can access them: GLOBAL_TENANCY_ID, GLOBAL_CSRF_TOKEN
/*
fetch('/confirm_upi_payment/' + tenancyId, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrfToken
    },
    body: JSON.stringify({
        status: 'completed',
        csrf_token: csrfToken
    })
})
.then(response => response.json())
.then(data => {
    if (data.success) {
        showPaymentStatusModal(
            `Payment verification request sent to owner. Reference: ${data.reference}`,
            true
        );
    } else {
        showPaymentStatusModal(data.message || 'Payment confirmation failed', false);
    }
});
*/