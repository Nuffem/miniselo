const {
    CLIENT_ID_LENGTH,
    MESSAGE_TYPES,
    ERROR_CODES,
    generateSecureKey,
    calculateClientId,
    encodeClientIdAnnouncement,
    decodeMessageFromServer, // For testing encodeClientIdAnnouncement
    encodeMessageToForward,
    decodeMessageFromClient, // For testing encodeMessageToForward
    encodeForwardedMessage,
    // decodeMessageFromServer will also be used for testing encodeForwardedMessage
    encodeErrorMessage
    // decodeMessageFromServer will also be used for testing encodeErrorMessage
} = require('./core');

describe('Core Utility Functions', () => {
    describe('generateSecureKey', () => {
        it('should return a Buffer', () => {
            expect(generateSecureKey()).toBeInstanceOf(Buffer);
        });

        it('should return a Buffer of 32 bytes', () => {
            expect(generateSecureKey().length).toBe(32);
        });

        it('should return different keys on subsequent calls', () => {
            const key1 = generateSecureKey();
            const key2 = generateSecureKey();
            expect(key1.equals(key2)).toBe(false);
        });
    });

    describe('calculateClientId', () => {
        const testKey = Buffer.from('testkey1234567890123456789012345'); // 32 bytes
        const testOrigin = 'https://example.com';

        it('should return a string', () => {
            expect(typeof calculateClientId(testKey, testOrigin)).toBe('string');
        });

        it(`should return a hex string of ${CLIENT_ID_LENGTH} characters`, () => {
            expect(calculateClientId(testKey, testOrigin).length).toBe(CLIENT_ID_LENGTH);
        });

        it('should return a consistent hash for the same key and origin', () => {
            const id1 = calculateClientId(testKey, testOrigin);
            const id2 = calculateClientId(testKey, testOrigin);
            expect(id1).toBe(id2);
        });

        it('should return a different hash for a different key', () => {
            const differentKey = Buffer.from('anotherkeyabcdefghijklmnopqrstuv');
            const id1 = calculateClientId(testKey, testOrigin);
            const id2 = calculateClientId(differentKey, testOrigin);
            expect(id1).not.toBe(id2);
        });

        it('should return a different hash for a different origin', () => {
            const differentOrigin = 'http://localhost:8080';
            const id1 = calculateClientId(testKey, testOrigin);
            const id2 = calculateClientId(testKey, differentOrigin);
            expect(id1).not.toBe(id2);
        });
    });

    describe('Binary Message Encoding/Decoding', () => {
        const testClientId = 'a'.repeat(CLIENT_ID_LENGTH);
        const testSenderId = 'b'.repeat(CLIENT_ID_LENGTH);
        const testRecipientId = 'c'.repeat(CLIENT_ID_LENGTH);
        const testMessage = "Hello, WebSocket!";
        const testShortMessage = "Hi";

        describe('ClientIdAnnouncement', () => {
            it('should correctly encode and decode a client ID announcement', () => {
                const encoded = encodeClientIdAnnouncement(testClientId);
                expect(encoded).toBeInstanceOf(Buffer);
                expect(encoded.length).toBe(1 + CLIENT_ID_LENGTH);
                expect(encoded.readUInt8(0)).toBe(MESSAGE_TYPES.CLIENT_ID_ANNOUNCEMENT);

                const decoded = decodeMessageFromServer(encoded);
                expect(decoded.type).toBe(MESSAGE_TYPES.CLIENT_ID_ANNOUNCEMENT);
                expect(decoded.clientId).toBe(testClientId);
            });

            it('should throw error for invalid client ID length on encode', () => {
                expect(() => encodeClientIdAnnouncement("invalid")).toThrow("Invalid client ID length");
            });
        });

        describe('MessageToForward (Client -> Server)', () => {
            it('should correctly encode and decode a message to forward', () => {
                const encoded = encodeMessageToForward(testRecipientId, testMessage);
                expect(encoded).toBeInstanceOf(Buffer);

                const payloadBuffer = Buffer.from(testMessage, 'utf-8');
                expect(encoded.length).toBe(1 + CLIENT_ID_LENGTH + 2 + payloadBuffer.length);
                expect(encoded.readUInt8(0)).toBe(MESSAGE_TYPES.MESSAGE_TO_FORWARD);

                const decoded = decodeMessageFromClient(encoded);
                expect(decoded.type).toBe(MESSAGE_TYPES.MESSAGE_TO_FORWARD);
                expect(decoded.recipientId).toBe(testRecipientId);
                expect(decoded.message).toBe(testMessage);
            });

             it('should correctly encode and decode a short message to forward', () => {
                const encoded = encodeMessageToForward(testRecipientId, testShortMessage);
                expect(encoded).toBeInstanceOf(Buffer);

                const payloadBuffer = Buffer.from(testShortMessage, 'utf-8');
                expect(encoded.length).toBe(1 + CLIENT_ID_LENGTH + 2 + payloadBuffer.length);
                expect(encoded.readUInt8(0)).toBe(MESSAGE_TYPES.MESSAGE_TO_FORWARD);

                const decoded = decodeMessageFromClient(encoded);
                expect(decoded.type).toBe(MESSAGE_TYPES.MESSAGE_TO_FORWARD);
                expect(decoded.recipientId).toBe(testRecipientId);
                expect(decoded.message).toBe(testShortMessage);
            });

            it('should throw error for invalid recipient ID length on encode', () => {
                expect(() => encodeMessageToForward("invalid", testMessage)).toThrow("Invalid recipient ID length");
            });
        });

        describe('ForwardedMessage (Server -> Client)', () => {
            it('should correctly encode and decode a forwarded message', () => {
                const encoded = encodeForwardedMessage(testSenderId, testMessage);
                expect(encoded).toBeInstanceOf(Buffer);

                const payloadBuffer = Buffer.from(testMessage, 'utf-8');
                expect(encoded.length).toBe(1 + CLIENT_ID_LENGTH + 2 + payloadBuffer.length);
                expect(encoded.readUInt8(0)).toBe(MESSAGE_TYPES.FORWARDED_MESSAGE);

                const decoded = decodeMessageFromServer(encoded);
                expect(decoded.type).toBe(MESSAGE_TYPES.FORWARDED_MESSAGE);
                expect(decoded.senderId).toBe(testSenderId);
                expect(decoded.message).toBe(testMessage);
            });

            it('should throw error for invalid sender ID length on encode', () => {
                expect(() => encodeForwardedMessage("invalid", testMessage)).toThrow("Invalid sender ID length");
            });
        });

        describe('ErrorMessage (Server -> Client)', () => {
            const testErrorCode = ERROR_CODES.RECIPIENT_NOT_FOUND;
            const testErrorMessageString = "The recipient you tried to reach is not connected.";

            it('should correctly encode and decode an error message', () => {
                const encoded = encodeErrorMessage(testErrorCode, testErrorMessageString);
                expect(encoded).toBeInstanceOf(Buffer);

                const errorMessageBuffer = Buffer.from(testErrorMessageString, 'utf-8');
                expect(encoded.length).toBe(1 + 1 + 2 + errorMessageBuffer.length);
                expect(encoded.readUInt8(0)).toBe(MESSAGE_TYPES.ERROR_MESSAGE);
                expect(encoded.readUInt8(1)).toBe(testErrorCode);

                const decoded = decodeMessageFromServer(encoded);
                expect(decoded.type).toBe(MESSAGE_TYPES.ERROR_MESSAGE);
                expect(decoded.code).toBe(testErrorCode);
                expect(decoded.message).toBe(testErrorMessageString);
            });
        });

        describe('Decoding Error Handling (decodeMessageFromClient)', () => {
            it('should handle message too short for header (MESSAGE_TO_FORWARD)', () => {
                const shortBuffer = Buffer.from([MESSAGE_TYPES.MESSAGE_TO_FORWARD]); // Too short
                const decoded = decodeMessageFromClient(shortBuffer);
                expect(decoded.type).toBe(MESSAGE_TYPES.ERROR_MESSAGE);
                expect(decoded.code).toBe(ERROR_CODES.INVALID_MESSAGE_FORMAT);
                expect(decoded.error).toContain('too short for header');
            });

            it('should handle empty message', () => {
                const emptyBuffer = Buffer.alloc(0);
                const decoded = decodeMessageFromClient(emptyBuffer);
                expect(decoded.type).toBe(MESSAGE_TYPES.ERROR_MESSAGE);
                expect(decoded.code).toBe(ERROR_CODES.INVALID_MESSAGE_FORMAT);
                expect(decoded.error).toContain('Message too short');
            });

            it('should handle message payload length mismatch', () => {
                const recipientIdBuffer = Buffer.from(testRecipientId, 'utf-8');
                // Stated payload length is 10, actual is 5 ("short")
                const statedPayloadLength = 10;
                const actualPayload = "short";
                const actualPayloadBuffer = Buffer.from(actualPayload, 'utf-8');

                const buffer = Buffer.alloc(1 + CLIENT_ID_LENGTH + 2 + actualPayloadBuffer.length);
                let offset = 0;
                buffer.writeUInt8(MESSAGE_TYPES.MESSAGE_TO_FORWARD, offset); offset += 1;
                recipientIdBuffer.copy(buffer, offset); offset += CLIENT_ID_LENGTH;
                buffer.writeUInt16BE(statedPayloadLength, offset); offset += 2; // Stating 10
                actualPayloadBuffer.copy(buffer, offset); // but only writing "short"

                // We need to test the case where the buffer is too short for the STATED length
                const bufferTooShortForStatedLength = Buffer.alloc(1 + CLIENT_ID_LENGTH + 2);
                let offset_2 = 0;
                bufferTooShortForStatedLength.writeUInt8(MESSAGE_TYPES.MESSAGE_TO_FORWARD, offset_2); offset_2 += 1;
                recipientIdBuffer.copy(bufferTooShortForStatedLength, offset_2); offset_2 += CLIENT_ID_LENGTH;
                // Stating a length that goes beyond the buffer's actual size
                bufferTooShortForStatedLength.writeUInt16BE(CLIENT_ID_LENGTH, offset_2);


                const decoded = decodeMessageFromClient(bufferTooShortForStatedLength);
                expect(decoded.type).toBe(MESSAGE_TYPES.ERROR_MESSAGE);
                expect(decoded.code).toBe(ERROR_CODES.INVALID_MESSAGE_FORMAT);
                expect(decoded.error).toContain('payload length mismatch');
            });
             it('should handle unknown message type', () => {
                const unknownTypeBuffer = Buffer.from([0xFF, 0x01, 0x02, 0x03]);
                const decoded = decodeMessageFromClient(unknownTypeBuffer);
                expect(decoded.type).toBe(MESSAGE_TYPES.ERROR_MESSAGE);
                expect(decoded.code).toBe(ERROR_CODES.INVALID_MESSAGE_FORMAT);
                expect(decoded.error).toContain('Unknown message type');
            });
        });

        describe('Decoding Error Handling (decodeMessageFromServer)', () => {
            it('should handle message too short for CLIENT_ID_ANNOUNCEMENT', () => {
                const shortBuffer = Buffer.from([MESSAGE_TYPES.CLIENT_ID_ANNOUNCEMENT]);
                const decoded = decodeMessageFromServer(shortBuffer);
                expect(decoded.type).toBe(MESSAGE_TYPES.ERROR_MESSAGE);
                expect(decoded.code).toBe(ERROR_CODES.INVALID_MESSAGE_FORMAT);
                expect(decoded.error).toContain('too short');
            });

            it('should handle message too short for FORWARDED_MESSAGE header', () => {
                const shortBuffer = Buffer.from([MESSAGE_TYPES.FORWARDED_MESSAGE]);
                const decoded = decodeMessageFromServer(shortBuffer);
                expect(decoded.type).toBe(MESSAGE_TYPES.ERROR_MESSAGE);
                expect(decoded.code).toBe(ERROR_CODES.INVALID_MESSAGE_FORMAT);
                expect(decoded.error).toContain('too short');
            });

            it('should handle message too short for ERROR_MESSAGE header', () => {
                const shortBuffer = Buffer.from([MESSAGE_TYPES.ERROR_MESSAGE, ERROR_CODES.INTERNAL_SERVER_ERROR]);
                const decoded = decodeMessageFromServer(shortBuffer);
                expect(decoded.type).toBe(MESSAGE_TYPES.ERROR_MESSAGE);
                expect(decoded.code).toBe(ERROR_CODES.INVALID_MESSAGE_FORMAT);
                expect(decoded.error).toContain('too short');
            });

            it('should handle unknown message type from server', () => {
                const unknownTypeBuffer = Buffer.from([0xFE, 0x01, 0x02, 0x03]);
                const decoded = decodeMessageFromServer(unknownTypeBuffer);
                expect(decoded.type).toBe(MESSAGE_TYPES.ERROR_MESSAGE);
                expect(decoded.code).toBe(ERROR_CODES.INVALID_MESSAGE_FORMAT);
                expect(decoded.error).toContain('Unknown message type from server');
            });
        });
    });
});
