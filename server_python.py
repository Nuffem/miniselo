import asyncio
import websockets
import http
from http.cookies import SimpleCookie
from pathlib import Path
import logging
import os # For potential future use, not strictly needed now

# Import from core_python
import core_python

# Configure basic logging
# BasicConfig should be called only once.
# If other modules also call it, it might not behave as expected.
# For more robust logging, get a specific logger.
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s %(name)s %(levelname)s: %(message)s'
)
# websockets_logger = logging.getLogger("websockets")
# websockets_logger.setLevel(logging.INFO) # Or logging.DEBUG for more verbosity
# websockets_logger.addHandler(logging.StreamHandler())


STATIC_FILES = {
    "/": {"path": "index.html", "type": "text/html"},
    "/index.html": {"path": "index.html", "type": "text/html"},
    "/client.js": {"path": "client.js", "type": "application/javascript"},
    "/locales/en.json": {"path": "locales/en.json", "type": "application/json"},
    "/locales/ptbr.json": {"path": "locales/ptbr.json", "type": "application/json"},
}
BASE_DIR = Path(__file__).resolve().parent

# Global state for WebSocket connections
connected_clients = {}  # Maps client_id_string to WebSocketServerProtocol object
COOKIE_NAME = 'ws-client-key'
# IS_SECURE_CONTEXT = False # Set to True if deploying with HTTPS

async def http_handler(path: str, request_headers: websockets.Headers):
    logger.debug(f"HTTP request: Path='{path}'")

    if path == "/health":
        logger.info("Serving /health endpoint.")
        headers = [('Content-Type', 'text/plain'), ('Cache-Control', 'no-cache')]
        return http.HTTPStatus.OK, headers, b"OK"

    if path in STATIC_FILES:
        file_info = STATIC_FILES[path]
        file_path = BASE_DIR / file_info["path"]
        logger.debug(f"Attempting to serve static file: {file_path}")

        try:
            with open(file_path, "rb") as f:
                content = f.read()
            response_headers = [
                ('Content-Type', file_info["type"]),
                ('Cache-Control', 'public, max-age=3600')
            ]
            logger.info(f"Serving static file {file_path} with Content-Type: {file_info['type']}")
            return http.HTTPStatus.OK, response_headers, content
        except FileNotFoundError:
            logger.warning(f"Static file not found: {file_path}")
            return http.HTTPStatus.NOT_FOUND, [('Content-Type', 'text/plain')], b"404 Not Found"
        except Exception as e:
            logger.error(f"Error reading static file {file_path}: {e}", exc_info=True)
            return http.HTTPStatus.INTERNAL_SERVER_ERROR, [('Content-Type', 'text/plain')], b"500 Internal Server Error"
    
    logger.debug(f"Path '{path}' not handled by HTTP, passing to WebSocket handler.")
    return None # Let websockets library handle it as a WebSocket upgrade request


async def websocket_handler(websocket: websockets.WebSocketServerProtocol, path: str):
    logger.info(f"Incoming WebSocket connection from {websocket.remote_address} for path '{path}'")
    client_key = None
    new_key_generated = False

    # 1. Cookie Logic
    cookie_header = websocket.request_headers.get('Cookie')
    if cookie_header:
        cookies = SimpleCookie()
        cookies.load(cookie_header)
        if COOKIE_NAME in cookies:
            try:
                key_hex = cookies[COOKIE_NAME].value
                # Validate hex string length (must be 64 for 32 bytes)
                if len(key_hex) == 64: 
                    potential_key = bytes.fromhex(key_hex)
                    if len(potential_key) == 32:  # core_python.generate_secure_key() produces 32 bytes
                        client_key = potential_key
                        logger.info(f"Existing valid key found in cookie for {websocket.remote_address}")
                    else:
                        # This case should ideally not happen if len(key_hex) == 64
                        logger.warning(f"Decoded key from cookie has invalid length for {websocket.remote_address}")
                else:
                    logger.warning(f"Invalid key hex length in cookie for {websocket.remote_address}. Expected 64, got {len(key_hex)}")
            except ValueError:
                logger.warning(f"Invalid hex format for key in cookie for {websocket.remote_address}")
        else:
            logger.info(f"Cookie '{COOKIE_NAME}' not found for {websocket.remote_address}")
    else:
        logger.info(f"No cookie header found for {websocket.remote_address}")

    if client_key is None:
        client_key = core_python.generate_secure_key()
        new_key_generated = True
        logger.info(f"Generated new key for {websocket.remote_address}: {client_key.hex()}")
        
        # Prepare Set-Cookie header value
        # Note on 'Secure' attribute: For production with HTTPS, add '; Secure'.
        # 'SameSite=None; Secure' is for cross-site usage.
        # 'SameSite=Lax' is a good default for non-HTTPS or same-site HTTPS.
        # Let's assume local HTTP development for now.
        # IS_SECURE = websocket.request_headers.get("x-forwarded-proto", "").lower() == "https" # Example for proxies
        # cookie_attributes = "Max-Age=31536000; HttpOnly; SameSite=Lax"
        # if IS_SECURE_CONTEXT: # Replace IS_SECURE_CONTEXT with actual check
        # cookie_attributes = "Max-Age=31536000; HttpOnly; Secure; SameSite=None" # If HTTPS
        
        cookie_attributes = "Max-Age=31536000; Path=/; HttpOnly; SameSite=Lax"
        cookie_value = f"{COOKIE_NAME}={client_key.hex()}; {cookie_attributes}"
        
        # This is the crucial part: set the cookie in the handshake response.
        # Modifying `websocket.response_headers` before the first send/recv (implicit accept)
        # or before an explicit `await websocket.accept()` is the way.
        websocket.response_headers['Set-Cookie'] = cookie_value
        logger.info(f"Prepared Set-Cookie header for new client: {cookie_value}")

    # 2. Client ID Calculation
    # The 'Origin' header might not always be present for non-browser clients or if explicitly removed.
    # Fallback to a unique identifier based on remote address if Origin is missing.
    client_origin = websocket.request_headers.get('Origin')
    if not client_origin: # Fallback if Origin is not present
        client_origin = f"ws://{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        logger.warning(f"No 'Origin' header for {websocket.remote_address}. Using fallback: {client_origin}")
        
    client_id_string = core_python.calculate_client_id(client_key, client_origin)
    logger.info(f"Calculated Client ID for {websocket.remote_address}: {client_id_string} (Origin: {client_origin})")

    # 3. Connection Management (before full handshake completion if new cookie is set)
    if client_id_string in connected_clients:
        logger.warning(f"Client ID {client_id_string} already connected. Closing new connection from {websocket.remote_address}.")
        # If a new cookie was to be set, it won't be because we close before handshake completes.
        # To ensure the client gets the *intended* ID (even if it's a duplicate),
        # we might let them connect, send ID, then close. But current logic is to reject early.
        try:
            await websocket.close(code=1008, reason='ID already connected') # 1008: Policy Violation
        except websockets.exceptions.ConnectionClosed:
            pass # Connection already closed by client or network
        return

    connected_clients[client_id_string] = websocket
    logger.info(f"Client connected: {client_id_string}. Total clients: {len(connected_clients)}")

    try:
        # Send Client ID Announcement (this will also send the handshake response including Set-Cookie if new)
        announcement_message = core_python.encode_client_id_announcement(client_id_string)
        await websocket.send(announcement_message)
        logger.info(f"Sent Client ID Announcement to {client_id_string}")

        # 4. Message Loop
        async for message_bytes in websocket:
            if not isinstance(message_bytes, bytes):
                logger.warning(f"Received non-bytes message from {client_id_string}: {type(message_bytes)}. Skipping.")
                error_msg_str = "Server expects binary messages."
                error_response = core_python.encode_error_message(core_python.ERROR_CODES['INVALID_MESSAGE_FORMAT'], error_msg_str)
                await websocket.send(error_response)
                continue

            logger.debug(f"Received binary message from {client_id_string}: {message_bytes.hex()[:60]}...") # Log first 30 bytes
            
            decoded_message = core_python.decode_message_from_client(message_bytes)
            
            if decoded_message['type'] == core_python.MESSAGE_TYPES['MESSAGE_TO_FORWARD']:
                recipient_id = decoded_message['recipient_id']
                message_text = decoded_message['message']
                logger.info(f"Message from {client_id_string} to {recipient_id}: '{message_text[:50]}...'")

                if recipient_id in connected_clients:
                    recipient_ws = connected_clients[recipient_id]
                    try:
                        forwarded_message = core_python.encode_forwarded_message(client_id_string, message_text)
                        await recipient_ws.send(forwarded_message)
                        logger.info(f"Forwarded message from {client_id_string} to {recipient_id}")
                    except websockets.exceptions.ConnectionClosed:
                        logger.warning(f"Recipient {recipient_id} disconnected before message could be sent from {client_id_string}.")
                        # Optionally, notify sender that recipient is gone.
                        error_msg_str = f"Recipient {recipient_id} has disconnected."
                        error_response = core_python.encode_error_message(core_python.ERROR_CODES['INVALID_RECIPIENT_ID'], error_msg_str) # Or a new error code
                        await websocket.send(error_response)
                    except Exception as e:
                        logger.error(f"Error sending message to {recipient_id}: {e}", exc_info=True)
                        error_msg_str = "Failed to send message to recipient due to an internal error."
                        error_response = core_python.encode_error_message(core_python.ERROR_CODES['UNKNOWN_ERROR'], error_msg_str)
                        await websocket.send(error_response)
                else:
                    logger.warning(f"Recipient {recipient_id} not found for message from {client_id_string}.")
                    error_msg_str = f"Recipient {recipient_id} not found or not connected."
                    error_response = core_python.encode_error_message(core_python.ERROR_CODES['INVALID_RECIPIENT_ID'], error_msg_str)
                    await websocket.send(error_response)
            
            elif decoded_message['type'] == core_python.MESSAGE_TYPES['ERROR_MESSAGE']: # Client reported an error from decoding
                # This means the client sent a message that *it* decoded as an error, or it's an error from core_python.decode_message_from_client
                logger.warning(f"Received error-type message from client {client_id_string} (or decode error): Code {decoded_message.get('code')}, Msg: {decoded_message.get('error')}")
                # Decide if we need to act on this, or just log it.
                # If it's from decode_message_from_client, we should send it back.
                if 'code' in decoded_message and 'error' in decoded_message: # Likely an error from our decode_message_from_client
                    error_response = core_python.encode_error_message(decoded_message['code'], decoded_message['error'])
                    await websocket.send(error_response)

            else: # Unknown message type or other error from decode_message_from_client
                logger.warning(f"Invalid or unknown message structure from {client_id_string}. Decoded: {decoded_message}")
                error_code = decoded_message.get('code', core_python.ERROR_CODES['INVALID_MESSAGE_FORMAT'])
                error_str = decoded_message.get('error', "Invalid or unknown message format received.")
                error_response = core_python.encode_error_message(error_code, error_str)
                await websocket.send(error_response)

    except websockets.exceptions.ConnectionClosedOK:
        logger.info(f"Client {client_id_string} disconnected gracefully (OK).")
    except websockets.exceptions.ConnectionClosedError as e:
        logger.warning(f"Client {client_id_string} connection closed with error: {e}")
    except Exception as e:
        logger.error(f"Unhandled error in WebSocket handler for {client_id_string}: {e}", exc_info=True)
        if websocket.open:
            try:
                error_response = core_python.encode_error_message(core_python.ERROR_CODES['UNKNOWN_ERROR'], "An unexpected server error occurred.")
                await websocket.send(error_response)
            except Exception as send_e:
                logger.error(f"Failed to send final error message to {client_id_string}: {send_e}")
    finally:
        removed_ws = connected_clients.pop(client_id_string, None)
        if removed_ws:
            logger.info(f"Client {client_id_string} removed from connected list. Total clients: {len(connected_clients)}")
        else:
            logger.warning(f"Client {client_id_string} was not found in connected_clients during cleanup. This might happen if connection was rejected early.")
        # Ensure connection is closed if not already
        if websocket.open:
            await websocket.close()
            logger.info(f"Ensured WebSocket connection is closed for {client_id_string}.")


async def main():
    host = "0.0.0.0"
    port = 8080

    # Setup logging (already done at module level, but can be more specific here if needed)
    logger.info(f"Starting HTTP and WebSocket server on ws://{host}:{port}")
    logger.info(f"Serving files from base directory: {BASE_DIR}")
    logger.info(f"Static files configured: {list(STATIC_FILES.keys())}")
    logger.info(f"WebSocket cookie name: '{COOKIE_NAME}'")

    # The process_request handles HTTP, returning None for WebSocket upgrades.
    # The websocket_handler then manages the WebSocket lifecycle.
    server_instance = websockets.serve(
        websocket_handler,
        host,
        port,
        process_request=http_handler,
        # logger=websockets_logger, # Pass a custom logger for websockets library messages
        # compression=None, # Explicitly disable compression if not needed or causing issues
    )

    async with server_instance:
        await asyncio.Future()  # Run forever until interrupted

def create_dummy_files_for_testing():
    # This function should ideally be run only if the files are missing and
    # it's a test/dev environment.
    logger.info("Ensuring dummy files exist for testing HTTP server...")
    (BASE_DIR / "locales").mkdir(exist_ok=True)
    
    dummy_files_content = {
        "index.html": "<html><head><title>WebSocket Test</title></head><body><h1>WebSocket Test Client</h1><p>Open console to see client ID and messages.</p><script src='client.js'></script></body></html>",
        "client.js": "console.log('Client.js loaded. Ready to connect to WebSocket.'); // Actual client logic is in the original client.js",
        "locales/en.json": "{\"greeting\": \"Hello\", \"app_name\": \"WS Forwarder\"}",
        "locales/ptbr.json": "{\"greeting\": \"Olá\", \"app_name\": \"Encaminhador WS\"}"
    }

    for rel_path, content in dummy_files_content.items():
        file_path = BASE_DIR / rel_path
        try:
            if not file_path.exists():
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                logger.info(f"Created dummy file: {file_path}")
        except Exception as e:
            logger.error(f"Could not create dummy file {file_path}: {e}", exc_info=True)

if __name__ == "__main__":
    create_dummy_files_for_testing() 
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server shutting down due to KeyboardInterrupt...")
    except Exception as e:
        logger.critical(f"Server failed to run: {e}", exc_info=True)
        # exit(1) # Consider exiting if server cannot start
