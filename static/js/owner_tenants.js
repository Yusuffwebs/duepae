// Function for sending payment-related messages
function sendWhatsAppMessage(buttonElement, phone, messageType, tenancyId, propertyName, rentAmount, dueDate, tenantName) {
    // Disable button to prevent multiple clicks
    buttonElement.disabled = true;
    buttonElement.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';

    // Get current date and time
    const now = new Date();
    const date = now.toLocaleDateString('en-IN');
    const time = now.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });

    // Construct appropriate message
    let message = '';
    if (messageType === 'payment_success') {
        message = `✅ *Payment Confirmation*\n\n` +
                 `🏠 *Property:* ${propertyName}\n`;
        if (tenantName) {
            message += `👨 *Tenant:* ${tenantName}\n`;
        }
        message += `💰 *Amount:* ₹${rentAmount}\n` +
                 `📅 *Date:* ${date}\n` +
                 `⏰ *Time:* ${time}\n\n` +
                 `_Thank you for your prompt payment!_`;
    }
    else if (messageType === 'payment_reminder') {
        message = `🔔 *Rent Payment Reminder*\n\n` +
                 `🏠 *Property:* ${propertyName}\n`;
        if (tenantName) {
            message += `👨 *Tenant:* ${tenantName}\n`;
        }
        message += `💰 *Amount Due:* ₹${rentAmount}\n` +
                 `📅 *Due Date:* ${dueDate}\n\n` +
                 `_Please make the payment at your earliest convenience._`;
    }

    sendMessageToWhatsApp(buttonElement, phone, message, messageType);
}

// Function for sending invitation messages
function sendInviteMessage(buttonElement, phone, tenancyId, propertyName, ownerName) {
    // Disable button to prevent multiple clicks
    buttonElement.disabled = true;
    buttonElement.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';

    // Construct invitation message
    const registrationLink = window.location.origin + "{{ url_for('register') }}" + "?phone=" + encodeURIComponent(phone);
    const message = `📲 *Invitation to RentTrack*\n\n` +
                   `Dear Tenant,\n\n` +
                   `You've been invited by ${ownerName} to manage your rent payments for ${propertyName}.\n\n` +
                   `Please register using this link:\n${registrationLink}\n\n` +
                   `_Looking forward to having you on our platform!_`;

    sendMessageToWhatsApp(buttonElement, phone, message, 'invitation');
}

// Common function to handle WhatsApp messaging
function sendMessageToWhatsApp(buttonElement, phone, message, messageType) {
    // Clean phone number (remove non-numeric characters)
    const cleanPhone = phone.replace(/\D/g, '');
    const encodedMessage = encodeURIComponent(message);

    // Determine the best WhatsApp URL based on platform
    const userAgent = navigator.userAgent;
    const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent);
    const isIOS = /iPhone|iPad|iPod/i.test(userAgent);
    const isInAppBrowser = /(FBAN|FBAV|Instagram|Twitter|Line|Snapchat)/i.test(userAgent);

    // Try different methods with fallbacks
    try {
        if (isInAppBrowser) {
            window.open(`https://api.whatsapp.com/send?phone=91${cleanPhone}&text=${encodedMessage}`, '_blank');
        }
        else if (isMobile) {
            if (isIOS) {
                window.location.href = `whatsapp://send?phone=91${cleanPhone}&text=${encodedMessage}`;
            } else {
                window.location.href = `intent://send/91${cleanPhone}?text=${encodedMessage}#Intent;scheme=smsto;package=com.whatsapp;action=android.intent.action.SENDTO;end`;
            }
        }
        else {
            window.open(`https://web.whatsapp.com/send?phone=91${cleanPhone}&text=${encodedMessage}`, '_blank');
        }
    } catch (e) {
        window.open(`https://api.whatsapp.com/send?phone=91${cleanPhone}&text=${encodedMessage}`, '_blank');
    }

    // Re-enable button after 3 seconds with appropriate icon
    setTimeout(() => {
        buttonElement.disabled = false;
        if (messageType === 'payment_success') {
            buttonElement.innerHTML = '<i class="fab fa-whatsapp"></i> Confirm';
        } else if (messageType === 'payment_reminder') {
            buttonElement.innerHTML = '<i class="fab fa-whatsapp"></i> Remind';
        } else if (messageType === 'invitation') {
            buttonElement.innerHTML = '<i class="fas fa-paper-plane"></i> Invite';
        }
    }, 3000);
}
