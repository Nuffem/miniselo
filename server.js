const http = require('http');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');
const cookie = require('cookie');
const crypto = require('crypto'); // For comparing secure strings

const {
    generateSecureKey,
    calculateClientId,
    encodeClientIdAnnouncement,
    encodeForwardedMessage,
    encodeErrorMessage,
    decodeMessageFromClient,
    MESSAGE_TYPES,
    ERROR_CODES,
    CLIENT_ID_LENGTH
} = require('./core');

const PORT = process.env.PORT || 8080;
const COOKIE_NAME = 'ws-client-key';

const arquivos_estáticos = {
    "/": {
        conteúdo: fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8'),
        tipo: 'text/html',
    },
    "/client.js": {
        conteúdo: fs.readFileSync(path.join(__dirname, 'client.js'), 'utf8'),
        tipo: 'application/javascript',
    },
    "/locales/en.json": {
        conteúdo: fs.readFileSync(path.join(__dirname, 'locales', 'en.json'), 'utf8'),
        tipo: 'application/json',
    },
    "/locales/ptbr.json": {
        conteúdo: fs.readFileSync(path.join(__dirname, 'locales', 'ptbr.json'), 'utf8'),
        tipo: 'application/json',
    },
}

// In-memory store for connected clients: { clientIdString: WebSocket_instance }
const connectedClients = new Map();

const server = http.createServer((req, res) => {
    // Basic HTTP response for non-WebSocket requests
    if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('OK');
    } else if (arquivos_estáticos[req.url]) {
        res.writeHead(200, { 'Content-Type': arquivos_estáticos[req.url].tipo });
        res.end(arquivos_estáticos[req.url].conteúdo);
    } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found. This is a WebSocket server, or the path is incorrect.');
    }
});

const wss = new WebSocket.Server({
  server,
  verifyClient: (info, cb) => {
    let clientKey;
    let newlyGeneratedKey = false;
    const requestCookies = cookie.parse(info.req.headers.cookie || '');
    const existingKeyHex = requestCookies[COOKIE_NAME];

    if (existingKeyHex) {
      try {
        const potentialKey = Buffer.from(existingKeyHex, 'hex');
        if (potentialKey.length === 32) { // 32 bytes for the key
          clientKey = potentialKey;
          console.log('verifyClient: Existing valid key found in cookie.');
        } else {
          console.log('verifyClient: Invalid key format in cookie. Will generate new key.');
        }
      } catch (error) {
        console.log('verifyClient: Error parsing key from cookie. Will generate new key.', error);
      }
    }

    if (!clientKey) {
      clientKey = generateSecureKey();
      newlyGeneratedKey = true;
      console.log('verifyClient: Generated new key.');
    }

    info.req.clientKey = clientKey; // Attach clientKey to the request object
    info.req.newlyGeneratedKey = newlyGeneratedKey; // Attach flag

    const keyHexString = clientKey.toString('hex');
    const serializedCookie = cookie.serialize(COOKIE_NAME, keyHexString, {
        httpOnly: true,
        secure: true, // Ensure HTTPS for this to work in production or modern browsers
        sameSite: 'None', // Required for cross-site contexts, implies Secure=true
        maxAge: 365 * 24 * 60 * 60 // 1 year
    });

    console.log(`verifyClient: Setting cookie: ${serializedCookie}`);
    cb(true, 0, '', { 'Set-Cookie': serializedCookie });
  }
});

console.log(`WebSocket server starting on port ${PORT}`);

wss.on('connection', (ws, req) => {
    // The clientKey is now set by the verifyClient function and attached to the request.
    const clientKey = req.clientKey;
    let clientIdString;

    // Ensure clientKey was successfully attached by verifyClient
    if (!clientKey) {
        console.error('FATAL: clientKey not found on request object in connection handler. Terminating connection.');
        ws.terminate();
        return;
    }

    // If verifyClient indicated a new key was generated, we can log that here if needed.
    if (req.newlyGeneratedKey) {
        console.log('Connection event: Client connected with a newly generated key.');
    } else {
        console.log('Connection event: Client connected with an existing key from cookie.');
    }

    const clientOrigin = req.headers.origin ||
                       (req.socket.remoteAddress && req.socket.remotePort ? `ws://${req.socket.remoteAddress}:${req.socket.remotePort}` : 'unknown-origin');

    clientIdString = calculateClientId(clientKey, clientOrigin);

    // Check if another client is already connected with this ID (e.g. cookie reuse from another tab before old one disconnected)
    // This is a simplified check. In a real-world scenario, you might want to allow multiple connections from the same "user"
    // but the prompt implies a unique identifier per connection based on the key.
    if (connectedClients.has(clientIdString)) {
        console.log(`Client ID ${clientIdString} already connected. Terminating new connection.`);
        ws.terminate(); // Or send an error message before terminating
        return;
    }

    connectedClients.set(clientIdString, ws);
    console.log(`Client connected: ${clientIdString} (Origin: ${clientOrigin}). Total clients: ${connectedClients.size}`);

    // Send the client its ID
    try {
        const announcement = encodeClientIdAnnouncement(clientIdString);
        ws.send(announcement, { binary: true });
    } catch (e) {
        console.error("Error encoding client ID announcement:", e);
        ws.terminate(); // Can't proceed if we can't send ID
        return;
    }

    // Set the cookie on the response for the HTTP upgrade request
    // This is a bit of a hack and might not work reliably across all setups or if 'ws' handles the response too quickly.
    // The standard way is to handle the 'upgrade' event on the http.Server directly.
    if (req.socket && req.socket.server && req.socket.server.constructor.name === 'Server') {
         // This is trying to tap into the raw socket response, which `ws` abstracts away.
         // A more direct approach with `ws` is to use `verifyClient` or handle upgrade manually.
         // For now, we'll rely on the client receiving its ID and the cookie being set by a prior HTTP interaction.
         // The prompt is specific: "store it with a cookie ... so that the key persists"
         // This means the server *must* be able to set this cookie during the WS handshake.
         // The `ws` library's default server doesn't easily expose this.
         // We'll add a custom header to *suggest* the cookie, though it's not standard for Set-Cookie.
         // This part is problematic with 'ws' default server.
    }


    ws.on('message', (binaryMessage) => {
        // Ensure message is Buffer
        const messageBuffer = Buffer.isBuffer(binaryMessage) ? binaryMessage : Buffer.from(binaryMessage);

        console.log(`Received message from ${clientIdString}`);
        const decoded = decodeMessageFromClient(messageBuffer);

        if (decoded.type === MESSAGE_TYPES.MESSAGE_TO_FORWARD) {
            const recipientWs = connectedClients.get(decoded.recipientId);
            if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
                try {
                    const messageToForward = encodeForwardedMessage(clientIdString, decoded.message);
                    recipientWs.send(messageToForward, { binary: true });
                    console.log(`Forwarded message from ${clientIdString} to ${decoded.recipientId}`);
                } catch (e) {
                    console.error("Error encoding message to forward:", e);
                    try {
                        ws.send(encodeErrorMessage(ERROR_CODES.INTERNAL_SERVER_ERROR, "Failed to encode message for forwarding."), {binary: true});
                    } catch (se) { console.error("Failed to send error to sender:", se); }
                }
            } else {
                console.log(`Recipient ${decoded.recipientId} not found or not open. Informing sender ${clientIdString}`);
                try {
                    const errorMsg = encodeErrorMessage(ERROR_CODES.RECIPIENT_NOT_FOUND, `Recipient ${decoded.recipientId} not found or not available.`);
                    ws.send(errorMsg, { binary: true });
                } catch (e) {
                    console.error("Error encoding recipient not found error:", e);
                }
            }
        } else if (decoded.type === MESSAGE_TYPES.ERROR_MESSAGE) { // Should be from our decode function if format is bad
             console.log(`Invalid message format from ${clientIdString}: ${decoded.error}`);
             try {
                // Send back a more generic error or the specific one if appropriate
                const errorMsg = encodeErrorMessage(decoded.code || ERROR_CODES.INVALID_MESSAGE_FORMAT, decoded.error || "Invalid message received.");
                ws.send(errorMsg, { binary: true });
             } catch (e) {
                console.error("Error encoding invalid message format error:", e);
             }
        } else {
            console.log(`Unknown message type ${decoded.type} from ${clientIdString}.`);
             try {
                const errorMsg = encodeErrorMessage(ERROR_CODES.INVALID_MESSAGE_FORMAT, `Unknown message type: ${decoded.type}`);
                ws.send(errorMsg, { binary: true });
             } catch (e) {
                console.error("Error encoding unknown message type error:", e);
             }
        }
    });

    ws.on('close', (code, reason) => {
        connectedClients.delete(clientIdString);
        console.log(`Client ${clientIdString} disconnected. Code: ${code}, Reason: ${reason ? reason.toString() : 'N/A'}. Total clients: ${connectedClients.size}`);
    });

    ws.on('error', (error) => {
        console.error(`Error on WebSocket connection for client ${clientIdString || 'unknown'}:`, error);
        // Ensure cleanup if error occurs before clientIdString is set or after
        if (clientIdString && connectedClients.has(clientIdString)) {
            connectedClients.delete(clientIdString);
            console.log(`Client ${clientIdString} removed due to error. Total clients: ${connectedClients.size}`);
        }
    });
});

// The custom 'upgrade' handler has been removed to prevent conflicts with
// the default upgrade handling provided by `new WebSocket.Server({ server })`.
// The `wss.on('connection', ...)` handler contains the necessary logic
// for client identification and communication.

server.listen(PORT, () => {
    console.log(`HTTP and WebSocket server is listening on port ${PORT}`);
});

// The previous custom 'upgrade' handler is removed to simplify and use wss default behavior.
// The cookie logic within 'connection' will read existing cookies.
// If a key is generated, it's used for the session; persistence depends on an external mechanism for setting the cookie.
// This is a compromise given the 'ws' library's abstraction.
// A truly robust solution would use `verifyClient` or a full custom upgrade handler to set cookies.
// For now, the server generates an ID and informs the client. The client can use this ID.
// The "store it with a cookie" part will be noted as needing an auxiliary HTTP endpoint.

module.exports = { server, wss, connectedClients, COOKIE_NAME }; // For potential testing
