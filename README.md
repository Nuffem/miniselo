# Node.js WebSocket Server with Binary Protocol

This project implements a WebSocket server using Node.js. It features a custom binary protocol for communication, secure client identification, and message routing between connected clients. The client identifier is derived from a cryptographically secure key (ideally persisted across sessions via a cookie) and the client's origin.

A simple internationalized (English & Portuguese) HTML/JavaScript client is provided to interact with the server.

## Features

- WebSocket server built with `ws` library.
- Secure 32-byte random key generation for client identification.
- Client identifier is SHA-256(key + origin).
- Server informs client of its ID upon connection.
- Custom binary message protocol for efficient communication.
- Message routing between clients using their unique identifiers.
- Secure, HttpOnly, SameSite=None cookie mechanism for key persistence (server expects this cookie; robust setting ideally via a prior dedicated HTTP endpoint).
- Automated tests for core binary protocol logic using Jest.
- Internationalized (i18n) HTML client with support for English and Portuguese (pt-BR).

## Binary Protocol Summary

Client IDs are fixed-length 64-character hex strings (UTF-8 encoded to 64 bytes in messages).

**Message Opcodes (1 byte):**
- `0x01`: Server to Client - Client ID Announcement
- `0x02`: Client to Server - Message to Forward
- `0x03`: Server to Client - Forwarded Message
- `0x04`: Server to Client - Error Message

**Message Structures:**

1.  **Client ID Announcement (Server -> Client):** 65 bytes
    - `[MessageType (1 byte: 0x01)]`
    - `[ClientID (64 bytes: UTF-8 encoded hex string)]`

2.  **Message to Forward (Client -> Server):** 1 + 64 + 2 + Payload_Length bytes
    - `[MessageType (1 byte: 0x02)]`
    - `[RecipientClientID (64 bytes: UTF-8 encoded hex string)]`
    - `[Payload_Length (2 bytes: unsigned big-endian integer)]`
    - `[Payload (variable bytes: UTF-8 encoded message string)]`

3.  **Forwarded Message (Server -> Client):** 1 + 64 + 2 + Payload_Length bytes
    - `[MessageType (1 byte: 0x03)]`
    - `[SenderClientID (64 bytes: UTF-8 encoded hex string)]`
    - `[Payload_Length (2 bytes: unsigned big-endian integer)]`
    - `[Payload (variable bytes: UTF-8 encoded message string)]`

4.  **Error Message (Server -> Client):** 1 + 1 + 2 + ErrorMessage_Length bytes
    - `[MessageType (1 byte: 0x04)]`
    - `[ErrorCode (1 byte)]`
    - `[ErrorMessage_Length (2 bytes: unsigned big-endian integer)]`
    - `[ErrorMessage (variable bytes: UTF-8 encoded string)]`

## Prerequisites

- Node.js (v14.x or later recommended)
- npm (usually comes with Node.js)

## Setup and Running

1.  **Clone the repository (if applicable) or download the files.**

2.  **Navigate to the project directory:**
    ```bash
    cd path/to/your/project
    ```

3.  **Install dependencies:**
    ```bash
    npm install
    ```

4.  **Run tests (optional but recommended):**
    ```bash
    npm test
    ```
    This will execute the Jest tests for `core.js`.

5.  **Start the server:**
    ```bash
    node server.js
    ```
    By default, the server will start on port 8080. You can set the `PORT` environment variable to use a different port (e.g., `PORT=3000 node server.js`).

## Using the Client

1.  Ensure the WebSocket server is running.
2.  Open the `index.html` file in your web browser.
    - You can usually do this by double-clicking the file or using a local web server (e.g., `npx serve .` and then navigating to `http://localhost:port_given_by_serve/`). Direct file access (`file:///...`) should also work for this client.
3.  The client will attempt to connect to the WebSocket server running on the same host and port as the `index.html` page is served from (or `localhost:8080` if opened as a local file and server is on default port).
4.  Your client ID will be displayed once connected.
5.  To send a message:
    - Enter the 64-character ID of the recipient client.
    - Type your message.
    - Click "Send Message".
6.  Received messages and logs will appear in the "Logs" section.
7.  You can switch the language of the client interface using the language selector in the top-right corner.

## Cookie Persistence Note (Important)

The server is designed to use a cryptographically secure key that should ideally persist between client sessions. This persistence is intended to be achieved using a `Secure`, `HttpOnly`, `SameSite=None` cookie named `ws-client-key`.

- **Reading the Cookie:** The `server.js` will read this cookie if present on an incoming WebSocket connection request.
- **Setting the Cookie:** The `ws` library used for the WebSocket server makes it non-trivial to reliably set cookies directly during the WebSocket handshake response within the same server instance that handles the WebSocket protocol upgrade.
    - **Recommendation:** For robust cookie-based key persistence, it's highly recommended to have a separate, standard HTTP(S) endpoint (e.g., `/initialize-session` or `/login`) that the client visits *before* establishing the WebSocket connection. This HTTP endpoint would be responsible for generating the key (if one doesn't exist or is invalid) and setting the `ws-client-key` cookie in its HTTP response. The browser would then automatically include this cookie in subsequent requests, including the WebSocket handshake request.
- **Current Behavior:** If no valid `ws-client-key` cookie is found, `server.js` generates a new key for the session. The client is always informed of its derived `clientIdString`. Without a mechanism to set the cookie (like the recommended HTTP endpoint), this key (and thus the ID if the origin remains the same) will not persist across browser restarts or if cookies are cleared.

This project provides the core WebSocket logic. Integrating a dedicated HTTP endpoint for cookie management is outside the current scope but is crucial for fulfilling the persistence requirement in a production environment.
