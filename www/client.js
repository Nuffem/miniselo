// Client-side binary protocol handling
const CLIENT_ID_LENGTH = 64; // SHA-256 hex string

const MESSAGE_TYPES = {
    CLIENT_ID_ANNOUNCEMENT: 0x01,
    MESSAGE_TO_FORWARD: 0x02, // Client sends this
    FORWARDED_MESSAGE: 0x03,  // Client receives this
    ERROR_MESSAGE: 0x04,      // Client receives this
};

const ERROR_CODES = { // For interpreting errors from server
    RECIPIENT_NOT_FOUND: 0x01,
    INVALID_MESSAGE_FORMAT: 0x02,
    INTERNAL_SERVER_ERROR: 0x03,
};

// Helper: TextEncoder/Decoder
const textEncoder = new TextEncoder(); // To encode strings to UTF-8
const textDecoder = new TextDecoder('utf-8'); // To decode UTF-8 to strings

/**
 * Encodes a message to be forwarded to another client (Client -> Server)
 * @param {string} recipientIdString - The recipient's client ID (64-char hex string).
 * @param {string} messageString - The message payload.
 * @returns {ArrayBuffer} The binary message.
 * @throws {Error} if recipientIdString is not the correct length.
 */
function encodeMessageToForward_client(recipientIdString, messageString) {
    if (recipientIdString.length !== CLIENT_ID_LENGTH) {
        throw new Error(`Invalid recipient ID length. Expected ${CLIENT_ID_LENGTH}, got ${recipientIdString.length}`);
    }
    const recipientIdBytes = textEncoder.encode(recipientIdString); // UTF-8 bytes
    const payloadBytes = textEncoder.encode(messageString);         // UTF-8 bytes

    const buffer = new ArrayBuffer(1 + CLIENT_ID_LENGTH + 2 + payloadBytes.byteLength);
    const view = new DataView(buffer);
    let offset = 0;

    view.setUint8(offset, MESSAGE_TYPES.MESSAGE_TO_FORWARD);
    offset += 1;

    new Uint8Array(buffer, offset, recipientIdBytes.byteLength).set(recipientIdBytes);
    offset += CLIENT_ID_LENGTH; // Assuming fixed byte length for ID after UTF-8 encoding for hex chars

    view.setUint16(offset, payloadBytes.byteLength, false); // false for Big Endian
    offset += 2;

    new Uint8Array(buffer, offset, payloadBytes.byteLength).set(payloadBytes);
    return buffer;
}

/**
 * Decodes an incoming binary message from the server (Server -> Client)
 * @param {ArrayBuffer} arrayBuffer - The incoming binary data from the server.
 * @returns {object} An object representing the decoded message.
 */
function decodeMessageFromServer_client(arrayBuffer) {
    const view = new DataView(arrayBuffer);
    if (arrayBuffer.byteLength < 1) {
        return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, message: 'Message too short (empty)' };
    }
    const messageType = view.getUint8(0);
    let offset = 1;

    try {
        switch (messageType) {
            case MESSAGE_TYPES.CLIENT_ID_ANNOUNCEMENT:
                if (arrayBuffer.byteLength < 1 + CLIENT_ID_LENGTH) {
                    return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, message: 'Message (ANNOUNCEMENT) too short' };
                }
                const clientIdBytes = new Uint8Array(arrayBuffer, offset, CLIENT_ID_LENGTH);
                const clientId = textDecoder.decode(clientIdBytes);
                return { type: MESSAGE_TYPES.CLIENT_ID_ANNOUNCEMENT, clientId: clientId };

            case MESSAGE_TYPES.FORWARDED_MESSAGE:
                if (arrayBuffer.byteLength < 1 + CLIENT_ID_LENGTH + 2) {
                    return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, message: 'Message (FORWARDED) too short for header' };
                }
                const senderIdBytes = new Uint8Array(arrayBuffer, offset, CLIENT_ID_LENGTH);
                const senderId = textDecoder.decode(senderIdBytes);
                offset += CLIENT_ID_LENGTH;

                const msgPayloadLength = view.getUint16(offset, false); // Big Endian
                offset += 2;

                if (arrayBuffer.byteLength < offset + msgPayloadLength) {
                    return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, message: 'Message (FORWARDED) payload length mismatch' };
                }
                const messageBytes = new Uint8Array(arrayBuffer, offset, msgPayloadLength);
                const message = textDecoder.decode(messageBytes);
                return { type: MESSAGE_TYPES.FORWARDED_MESSAGE, senderId: senderId, message: message };

            case MESSAGE_TYPES.ERROR_MESSAGE:
                if (arrayBuffer.byteLength < 1 + 1 + 2) { // Type + ErrorCode + ErrorMsgLength
                     return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, message: 'Message (ERROR) too short for header' };
                }
                const errorCode = view.getUint8(offset);
                offset += 1;
                const errorMessageLength = view.getUint16(offset, false); // Big Endian
                offset += 2;
                if (arrayBuffer.byteLength < offset + errorMessageLength) {
                    return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, message: 'Message (ERROR) payload length mismatch' };
                }
                const errorMessageBytes = new Uint8Array(arrayBuffer, offset, errorMessageLength);
                const errorMsgStr = textDecoder.decode(errorMessageBytes);
                return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: errorCode, message: errorMsgStr };

            default:
                return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, message: `Unknown message type from server: ${messageType}` };
        }
    } catch (e) {
        console.error("Error during client-side decoding:", e);
        return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, message: `Client-side decoding exception: ${e.message}` };
    }
}

// --- End of re-implemented core logic ---

let ws;
let currentLocale = 'en';
let translations = {};
let myClientId = null;

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

function logMessage(message, type = 'info') {
    const logsDiv = $('#logs');
    const time = new Date().toLocaleTimeString();
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry log-${type}`;
    logEntry.textContent = `[${time}] ${message}`;
    logsDiv.appendChild(logEntry);
    logsDiv.scrollTop = logsDiv.scrollHeight;
}

async function loadTranslations(lang) {
    try {
        const response = await fetch(`locales/${lang}.json`);
        if (!response.ok) {
            throw new Error(`Failed to load ${lang}.json: ${response.statusText}`);
        }
        translations = await response.json();
        applyTranslations();
        currentLocale = lang;
        localStorage.setItem('preferredLang', lang);
        document.documentElement.lang = lang.split('-')[0]; // Set html lang attribute
    } catch (error) {
        console.error("Error loading translations:", error);
        logMessage(`Error loading translations for ${lang}. Falling back to English if available.`, 'error');
        if (lang !== 'en') { // Avoid infinite loop if English fails
            await loadTranslations('en');
        }
    }
}

function t(key) {
    return translations[key] || key;
}

function applyTranslations() {
    document.title = t('pageTitle');
    $$('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
            if (el.placeholder) el.placeholder = t(key);
            else el.value = t(key);
        } else {
            el.textContent = t(key);
        }
    });
}

function updateConnectionStatus(statusKey, id = null) {
    $('#connectionStatus').textContent = t(statusKey);
    if (id) {
        $('#clientId').textContent = id;
        myClientId = id;
    } else if (statusKey === 'notConnected' || statusKey === 'connecting') {
        $('#clientId').textContent = t('noId');
        myClientId = null;
    }
}

function connect() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    ws = new WebSocket(`${protocol}//${host}`);
    ws.binaryType = 'arraybuffer'; // Crucial for binary messages

    updateConnectionStatus('connecting');

    ws.onopen = () => {
        updateConnectionStatus('connected');
        logMessage('Connected to WebSocket server.');
    };

    ws.onmessage = (event) => {
        const arrayBuffer = event.data;
        const decodedMessage = decodeMessageFromServer_client(arrayBuffer);

        if (decodedMessage.type === MESSAGE_TYPES.CLIENT_ID_ANNOUNCEMENT) {
            updateConnectionStatus('connectedWithId', decodedMessage.clientId);
            logMessage(`${t('connectedWithId')} ${decodedMessage.clientId}`);
        } else if (decodedMessage.type === MESSAGE_TYPES.FORWARDED_MESSAGE) {
            logMessage(`${t('messageReceivedFrom')} ${decodedMessage.senderId}: ${decodedMessage.message}`);
        } else if (decodedMessage.type === MESSAGE_TYPES.ERROR_MESSAGE) {
            logMessage(`${t('errorFromServer')} (Code ${decodedMessage.code}): ${decodedMessage.message}`, 'error');
        } else {
            logMessage(t('errorDecoding'), 'error');
            console.error("Unknown decoded message structure:", decodedMessage);
        }
    };

    ws.onclose = () => {
        updateConnectionStatus('notConnected');
        logMessage(t('disconnected'), 'warning');
        ws = null;
    };

    ws.onerror = (error) => {
        logMessage(`WebSocket error: ${error.message || 'Unknown error'}`, 'error');
        console.error("WebSocket error:", error);
        updateConnectionStatus('notConnected');
        ws = null;
    };
}

function sendMessage() {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        logMessage('Not connected. Cannot send message.', 'error');
        return;
    }

    const recipientId = $('#recipientId').value.trim();
    const message = $('#message').value;

    if (!recipientId || recipientId.length !== CLIENT_ID_LENGTH) {
        logMessage(`Recipient ID must be ${CLIENT_ID_LENGTH} characters long.`, 'error');
        return;
    }
    if (!message) {
        logMessage('Message cannot be empty.', 'error');
        return;
    }

    try {
        const encodedMessage = encodeMessageToForward_client(recipientId, message);
        ws.send(encodedMessage);
        logMessage(`${t('messageSent')} ${recipientId}: ${message}`);
        $('#message').value = ''; // Clear message input
    } catch (e) {
        logMessage(`${t('errorEncoding')}: ${e.message}`, 'error');
        console.error("Error encoding message:", e);
    }
}


document.addEventListener('DOMContentLoaded', async () => {
    const preferredLang = localStorage.getItem('preferredLang') || navigator.language.split('-')[0] || 'en';
    const langSelector = $('#langSelector');

    // Populate language selector
    ['en', 'ptbr'].forEach(lang => {
        const option = document.createElement('option');
        option.value = lang;
        option.textContent = lang === 'en' ? 'English' : 'Português (BR)';
        if (lang === preferredLang) {
            option.selected = true;
        }
        langSelector.appendChild(option);
    });

    await loadTranslations(preferredLang);

    $('#connectButton').addEventListener('click', connect);
    $('#sendButton').addEventListener('click', sendMessage);
    $('#clearLogsButton').addEventListener('click', () => {
        $('#logs').innerHTML = '';
    });
    langSelector.addEventListener('change', (event) => {
        loadTranslations(event.target.value);
    });

    // Attempt to connect automatically if desired, or wait for button click
    // connect(); // Uncomment to connect automatically on load
});
