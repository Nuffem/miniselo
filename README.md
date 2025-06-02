# WebSocket Server with Binary Protocol (Node.js & Python)

This project implements a WebSocket server featuring a custom binary protocol for communication, secure client identification, and message routing between connected clients. The client identifier is derived from a cryptographically secure key (ideally persisted across sessions via a cookie) and the client's origin. Implementations are provided in both Node.js and Python.

A simple internationalized (English & Portuguese) HTML/JavaScript client is provided to interact with the server.

## Features

- WebSocket server implementations:
    - Node.js: using the `ws` library.
    - Python: using the `websockets` library.
- Secure 32-byte random key generation for client identification.
- Client identifier is SHA-256(key + origin).
- Server informs client of its ID upon connection.
- Custom binary message protocol for efficient communication (common to both servers).
- Message routing between clients using their unique identifiers.
- Secure, HttpOnly cookie mechanism for key persistence (`ws-client-key`).
    - **Python Server:** Sets the cookie directly during WebSocket handshake if a new key is generated.
    - **Node.js Server:** Expects this cookie; robust setting ideally via a prior dedicated HTTP endpoint (see "Cookie Persistence Note").
- Automated tests for core binary protocol logic (Jest for Node.js `core.js`).
- Internationalized (i18n) HTML client with support for English and Portuguese (pt-BR).

## Binary Protocol Summary

This protocol is used by both the Node.js and Python server implementations. Client IDs are fixed-length 64-character hex strings (UTF-8 encoded to 64 bytes in messages).

**Message Opcodes (1 byte):**
- `0x00` (Python `core_python.py`): Server to Client - Client ID Announcement
- `0x01` (Python `core_python.py`): Server to Client - Forwarded Message
- `0x02` (Python `core_python.py`): Server to Client - Error Message
- `0x03` (Python `core_python.py`): Client to Server - Message to Forward

*(Note: Original Node.js `core.js` used different opcodes: `0x01` for Announcement, `0x02` for Message to Forward, `0x03` for Forwarded Message, `0x04` for Error. The client `client.js` and server implementations should be aligned with the opcodes defined in their respective `core` files. The Python section above reflects `core_python.py`.)*

**Message Structures (Conceptual - refer to specific `core.js` or `core_python.py` for exact opcodes):**

1.  **Client ID Announcement (Server -> Client):** 65 bytes
    - `[MessageType (1 byte)]`
    - `[ClientID (64 bytes: UTF-8 encoded hex string)]`

2.  **Message to Forward (Client -> Server):** 1 + 64 + 2 + Payload_Length bytes
    - `[MessageType (1 byte)]`
    - `[RecipientClientID (64 bytes: UTF-8 encoded hex string)]`
    - `[Payload_Length (2 bytes: unsigned big-endian integer)]`
    - `[Payload (variable bytes: UTF-8 encoded message string)]`

3.  **Forwarded Message (Server -> Client):** 1 + 64 + 2 + Payload_Length bytes
    - `[MessageType (1 byte)]`
    - `[SenderClientID (64 bytes: UTF-8 encoded hex string)]`
    - `[Payload_Length (2 bytes: unsigned big-endian integer)]`
    - `[Payload (variable bytes: UTF-8 encoded message string)]`

4.  **Error Message (Server -> Client):** 1 + 1 + 2 + ErrorMessage_Length bytes
    - `[MessageType (1 byte)]`
    - `[ErrorCode (1 byte)]`
    - `[ErrorMessage_Length (2 bytes: unsigned big-endian integer)]`
    - `[ErrorMessage (variable bytes: UTF-8 encoded string)]`

---

## Python WebSocket Server

This is the recommended server implementation due to its improved cookie handling.

### Prerequisites for Python Server
- Python 3.7+ (asyncio and modern `websockets` library features).
- `websockets` library.

### Setup and Running the Python Server
1.  **Clone the repository (if applicable) or download the files (`server_python.py`, `core_python.py`, and the `static` directory contents).**

2.  **Navigate to the project directory:**
    ```bash
    cd path/to/your/project
    ```

3.  **Install dependencies:**
    ```bash
    pip install websockets
    ```

4.  **Start the server:**
    ```bash
    python server_python.py
    ```
    By default, the server will start on `http://localhost:8080` (for static files like `index.html`, `client.js`) and `ws://localhost:8080` (for WebSocket connections). Server logs will be printed to the console.

---

## Node.js WebSocket Server (Legacy)

This section describes the original Node.js server implementation.

### Prerequisites for Node.js Server
- Node.js (v14.x or later recommended)
- npm (usually comes with Node.js)

### Node.js Server Setup
1.  **Clone the repository (if applicable) or download the files (`server.js`, `core.js`, `package.json`, and the `static` directory contents).**

2.  **Navigate to the project directory:**
    ```bash
    cd path/to/your/project
    ```

3.  **Install dependencies:**
    ```bash
    npm install
    ```

4.  **Run tests (optional but recommended for `core.js`):**
    ```bash
    npm test
    ```

5.  **Start the server:**
    ```bash
    node server.js
    ```
    By default, the server will start on port 8080. You can set the `PORT` environment variable to use a different port (e.g., `PORT=3000 node server.js`).

---

## Using the Client (`index.html`)

The client is designed to work with either the Python or Node.js WebSocket server.

1.  Ensure your chosen WebSocket server (Python or Node.js) is running.
2.  Open the `index.html` file (located in the `static` directory or the project root, depending on your setup) in your web browser.
    - If using the Python server, it serves `index.html` from the root path: `http://localhost:8080/`.
    - If serving `index.html` via other means (e.g., `file:///...` or `npx serve`), ensure `client.js` correctly points to your running WebSocket server's address (default `ws://localhost:8080`).
3.  Your client ID will be displayed once connected.
4.  To send a message:
    - Enter the 64-character ID of the recipient client.
    - Type your message.
    - Click "Send Message".
5.  Received messages and logs will appear in the "Logs" section.
6.  You can switch the language of the client interface using the language selector in the top-right corner.

## Cookie Persistence Note (Important)

The server is designed to use a cryptographically secure key (`ws-client-key`) that should ideally persist between client sessions. This allows a client to maintain its derived `clientIdString` if its origin also remains the same.

### Python Server (`server_python.py`)
The Python server implementation using the `websockets` library **directly handles setting the `ws-client-key` cookie**.
- If a connecting client does not present a valid `ws-client-key` cookie, the Python server generates a new key.
- This new key is then sent back to the client via a `Set-Cookie` header as part of the WebSocket handshake response.
- This mechanism ensures that key persistence works as intended out-of-the-box with the Python server, without requiring a separate HTTP endpoint for cookie setting. The cookie is set with `HttpOnly`, `SameSite=Lax` (suitable for local HTTP development; `Secure` attribute would be added for HTTPS), and `Max-Age` attributes.

### Node.js Server (`server.js`)
The Node.js server implementation using the `ws` library has limitations in directly setting cookies during the WebSocket handshake.
- **Reading the Cookie:** `server.js` will read the `ws-client-key` cookie if present on an incoming WebSocket connection request.
- **Setting the Cookie Challenge:** The `ws` library makes it non-trivial to reliably set cookies directly during the WebSocket handshake response.
    - **Recommendation for Node.js:** For robust cookie-based key persistence with the Node.js server, it's highly recommended to have a separate, standard HTTP(S) endpoint (e.g., `/initialize-session` or `/login`) that the client visits *before* establishing the WebSocket connection. This HTTP endpoint would be responsible for generating the key (if one doesn't exist or is invalid) and setting the `ws-client-key` cookie in its HTTP response. The browser would then automatically include this cookie in subsequent requests, including the WebSocket handshake request.
- **Node.js Behavior without External Cookie Setting:** If no valid `ws-client-key` cookie is found, `server.js` generates a new key for the session. Without an external mechanism to set the cookie, this key (and thus the ID if the origin remains the same) will not persist across browser restarts or if cookies are cleared when using the Node.js server.

For the most straightforward experience with cookie persistence, **the Python server is recommended.**
