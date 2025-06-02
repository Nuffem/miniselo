const crypto = require('crypto');

const CLIENT_ID_LENGTH = 64; // SHA-256 hex string

const MESSAGE_TYPES = {
    CLIENT_ID_ANNOUNCEMENT: 0x01,
    MESSAGE_TO_FORWARD: 0x02,
    FORWARDED_MESSAGE: 0x03,
    ERROR_MESSAGE: 0x04,
};

const ERROR_CODES = {
    RECIPIENT_NOT_FOUND: 0x01,
    INVALID_MESSAGE_FORMAT: 0x02,
    INTERNAL_SERVER_ERROR: 0x03,
};

/**
 * Generates a cryptographically secure 32-byte random key.
 * @returns {Buffer} A 32-byte buffer containing the random key.
 */
function generateSecureKey() {
    return crypto.randomBytes(32);
}

/**
 * Calculates a fixed-length string representation (hex) of the SHA-256 hash
 * of the concatenation of a key and an origin string.
 * @param {Buffer} key - The client's secret key.
 * @param {string} origin - The origin of the client's request.
 * @returns {string} A 64-character hex string representing the client ID.
 */
function calculateClientId(key, origin) {
    const hash = crypto.createHash('sha256');
    hash.update(key);
    hash.update(origin);
    return hash.digest('hex'); // Results in a 64-character string
}

/**
 * Encodes the client ID announcement message.
 * Server -> Client
 * @param {string} clientIdString - The client's ID (64-char hex string).
 * @returns {Buffer} The binary message.
 */
function encodeClientIdAnnouncement(clientIdString) {
    if (clientIdString.length !== CLIENT_ID_LENGTH) {
        throw new Error(`Invalid client ID length. Expected ${CLIENT_ID_LENGTH}, got ${clientIdString.length}`);
    }
    const clientIdBuffer = Buffer.from(clientIdString, 'utf-8');
    const buffer = Buffer.alloc(1 + CLIENT_ID_LENGTH);
    buffer.writeUInt8(MESSAGE_TYPES.CLIENT_ID_ANNOUNCEMENT, 0);
    clientIdBuffer.copy(buffer, 1);
    return buffer;
}

/**
 * Encodes a message to be forwarded to another client.
 * Client -> Server
 * @param {string} recipientIdString - The recipient's client ID (64-char hex string).
 * @param {string} messageString - The message payload.
 * @returns {Buffer} The binary message.
 */
function encodeMessageToForward(recipientIdString, messageString) {
    if (recipientIdString.length !== CLIENT_ID_LENGTH) {
        throw new Error(`Invalid recipient ID length. Expected ${CLIENT_ID_LENGTH}, got ${recipientIdString.length}`);
    }
    const recipientIdBuffer = Buffer.from(recipientIdString, 'utf-8');
    const payloadBuffer = Buffer.from(messageString, 'utf-8');

    // MessageType (1) + RecipientID (64) + PayloadLength (2) + Payload
    const buffer = Buffer.alloc(1 + CLIENT_ID_LENGTH + 2 + payloadBuffer.length);
    let offset = 0;
    buffer.writeUInt8(MESSAGE_TYPES.MESSAGE_TO_FORWARD, offset);
    offset += 1;
    recipientIdBuffer.copy(buffer, offset);
    offset += CLIENT_ID_LENGTH;
    buffer.writeUInt16BE(payloadBuffer.length, offset);
    offset += 2;
    payloadBuffer.copy(buffer, offset);
    return buffer;
}

/**
 * Encodes a forwarded message from one client to another, via the server.
 * Server -> Client
 * @param {string} senderIdString - The sender's client ID (64-char hex string).
 * @param {string} messageString - The message payload.
 * @returns {Buffer} The binary message.
 */
function encodeForwardedMessage(senderIdString, messageString) {
    if (senderIdString.length !== CLIENT_ID_LENGTH) {
        throw new Error(`Invalid sender ID length. Expected ${CLIENT_ID_LENGTH}, got ${senderIdString.length}`);
    }
    const senderIdBuffer = Buffer.from(senderIdString, 'utf-8');
    const payloadBuffer = Buffer.from(messageString, 'utf-8');

    // MessageType (1) + SenderID (64) + PayloadLength (2) + Payload
    const buffer = Buffer.alloc(1 + CLIENT_ID_LENGTH + 2 + payloadBuffer.length);
    let offset = 0;
    buffer.writeUInt8(MESSAGE_TYPES.FORWARDED_MESSAGE, offset);
    offset += 1;
    senderIdBuffer.copy(buffer, offset);
    offset += CLIENT_ID_LENGTH;
    buffer.writeUInt16BE(payloadBuffer.length, offset);
    offset += 2;
    payloadBuffer.copy(buffer, offset);
    return buffer;
}

/**
 * Encodes an error message.
 * Server -> Client
 * @param {number} errorCode - One of ERROR_CODES.
 * @param {string} errorMessageString - A descriptive error message.
 * @returns {Buffer} The binary message.
 */
function encodeErrorMessage(errorCode, errorMessageString) {
    const errorMessageBuffer = Buffer.from(errorMessageString, 'utf-8');
    // MessageType (1) + ErrorCode (1) + ErrorMessageLength (2) + ErrorMessage
    const buffer = Buffer.alloc(1 + 1 + 2 + errorMessageBuffer.length);
    let offset = 0;
    buffer.writeUInt8(MESSAGE_TYPES.ERROR_MESSAGE, offset);
    offset += 1;
    buffer.writeUInt8(errorCode, offset);
    offset += 1;
    buffer.writeUInt16BE(errorMessageBuffer.length, offset);
    offset += 2;
    errorMessageBuffer.copy(buffer, offset);
    return buffer;
}


/**
 * Decodes an incoming binary message from a client.
 * This will primarily be used by the server to decode messages of type MESSAGE_TO_FORWARD.
 * @param {Buffer} binaryMessage - The incoming binary data.
 * @returns {object} An object like { type: MESSAGE_TYPES.MESSAGE_TO_FORWARD, recipientId: '...', message: '...' }
 *                   or { type: MESSAGE_TYPES.ERROR_MESSAGE, error: 'Error description' } if parsing fails or for other types.
 */
function decodeMessageFromClient(binaryMessage) {
    if (binaryMessage.length < 1) {
        return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, error: 'Message too short' };
    }
    const messageType = binaryMessage.readUInt8(0);
    let offset = 1;

    switch (messageType) {
        case MESSAGE_TYPES.MESSAGE_TO_FORWARD:
            if (binaryMessage.length < 1 + CLIENT_ID_LENGTH + 2) {
                return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, error: 'Message (type TO_FORWARD) too short for header' };
            }
            const recipientId = binaryMessage.toString('utf-8', offset, offset + CLIENT_ID_LENGTH);
            offset += CLIENT_ID_LENGTH;
            const payloadLength = binaryMessage.readUInt16BE(offset);
            offset += 2;
            if (binaryMessage.length < offset + payloadLength) {
                return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, error: 'Message (type TO_FORWARD) payload length mismatch' };
            }
            const message = binaryMessage.toString('utf-8', offset, offset + payloadLength);
            return {
                type: MESSAGE_TYPES.MESSAGE_TO_FORWARD,
                recipientId: recipientId,
                message: message,
            };
        // Add other cases here if clients are expected to send other message types.
        // For now, server primarily expects MESSAGE_TO_FORWARD from clients.
        default:
            return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, error: `Unknown message type: ${messageType}` };
    }
}

/**
 * Decodes an incoming binary message from the server.
 * This will primarily be used by the client.
 * @param {Buffer} binaryMessage - The incoming binary data from the server.
 * @returns {object} An object representing the decoded message.
 *                   e.g., { type: MESSAGE_TYPES.CLIENT_ID_ANNOUNCEMENT, clientId: '...' }
 *                   e.g., { type: MESSAGE_TYPES.FORWARDED_MESSAGE, senderId: '...', message: '...' }
 *                   e.g., { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ..., message: '...' }
 */
function decodeMessageFromServer(binaryMessage) {
    if (binaryMessage.length < 1) {
        return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, error: 'Message too short' };
    }
    const messageType = binaryMessage.readUInt8(0);
    let offset = 1;

    switch (messageType) {
        case MESSAGE_TYPES.CLIENT_ID_ANNOUNCEMENT:
            if (binaryMessage.length < 1 + CLIENT_ID_LENGTH) {
                return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, error: 'Message (type ANNOUNCEMENT) too short' };
            }
            const clientId = binaryMessage.toString('utf-8', offset, offset + CLIENT_ID_LENGTH);
            return {
                type: MESSAGE_TYPES.CLIENT_ID_ANNOUNCEMENT,
                clientId: clientId,
            };

        case MESSAGE_TYPES.FORWARDED_MESSAGE:
            if (binaryMessage.length < 1 + CLIENT_ID_LENGTH + 2) {
                return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, error: 'Message (type FORWARDED) too short for header' };
            }
            const senderId = binaryMessage.toString('utf-8', offset, offset + CLIENT_ID_LENGTH);
            offset += CLIENT_ID_LENGTH;
            const msgPayloadLength = binaryMessage.readUInt16BE(offset);
            offset += 2;
            if (binaryMessage.length < offset + msgPayloadLength) {
                return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, error: 'Message (type FORWARDED) payload length mismatch' };
            }
            const message = binaryMessage.toString('utf-8', offset, offset + msgPayloadLength);
            return {
                type: MESSAGE_TYPES.FORWARDED_MESSAGE,
                senderId: senderId,
                message: message,
            };

        case MESSAGE_TYPES.ERROR_MESSAGE:
            if (binaryMessage.length < 1 + 1 + 2) {
                 return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, error: 'Message (type ERROR) too short for header' };
            }
            const errorCode = binaryMessage.readUInt8(offset);
            offset += 1;
            const errorMessageLength = binaryMessage.readUInt16BE(offset);
            offset += 2;
            if (binaryMessage.length < offset + errorMessageLength) {
                return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, error: 'Message (type ERROR) payload length mismatch' };
            }
            const errorMessage = binaryMessage.toString('utf-8', offset, offset + errorMessageLength);
            return {
                type: MESSAGE_TYPES.ERROR_MESSAGE,
                code: errorCode,
                message: errorMessage,
            };

        default:
            return { type: MESSAGE_TYPES.ERROR_MESSAGE, code: ERROR_CODES.INVALID_MESSAGE_FORMAT, error: `Unknown message type from server: ${messageType}` };
    }
}


module.exports = {
    CLIENT_ID_LENGTH,
    MESSAGE_TYPES,
    ERROR_CODES,
    generateSecureKey,
    calculateClientId,
    encodeClientIdAnnouncement,
    encodeMessageToForward, // Used by client to send
    encodeForwardedMessage, // Used by server to forward
    encodeErrorMessage,     // Used by server to send errors
    decodeMessageFromClient,// Used by server to decode
    decodeMessageFromServer // Used by client to decode
};
