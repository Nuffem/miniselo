#!/bin/bash

# Function to kill the server
cleanup() {
    echo "Cleaning up..."
    if [ ! -z "$server_pid" ]; then
        kill $server_pid
        echo "Server killed."
    fi
}

# Trap EXIT signal to ensure cleanup
trap cleanup EXIT

echo "Starting server..."
node server.js &
server_pid=$!
echo "Server PID: $server_pid"

# Wait for the server to start
sleep 2

# --- Test Root Path ---
echo "Testing GET / (index.html)"
response_root=$(curl -is http://localhost:8080/)
echo "$response_root"

# Check status code
if echo "$response_root" | grep -q "HTTP/1.1 200 OK"; then
    echo "GET /: Status 200 OK - PASSED"
else
    echo "GET /: Status 200 OK - FAILED"
    exit 1
fi

# Check Content-Type
if echo "$response_root" | grep -q "Content-Type: text/html"; then
    echo "GET /: Content-Type text/html - PASSED"
else
    echo "GET /: Content-Type text/html - FAILED"
    exit 1
fi

# Check content (simple check for a known string from the actual index.html)
if echo "$response_root" | grep -q "<title data-i18n=\"pageTitle\">WebSocket Binary Client</title>"; then
    echo "GET /: Content contains '<title data-i18n=\"pageTitle\">WebSocket Binary Client</title>' - PASSED"
else
    echo "GET /: Content check - FAILED"
    exit 1
fi

# --- Test /health Path ---
echo -e "\nTesting GET /health"
response_health=$(curl -is http://localhost:8080/health)
echo "$response_health"

# Check status code
if echo "$response_health" | grep -q "HTTP/1.1 200 OK"; then
    echo "GET /health: Status 200 OK - PASSED"
else
    echo "GET /health: Status 200 OK - FAILED"
    exit 1
fi

# Check Content-Type
if echo "$response_health" | grep -q "Content-Type: text/plain"; then
    echo "GET /health: Content-Type text/plain - PASSED"
else
    echo "GET /health: Content-Type text/plain - FAILED"
    exit 1
fi

# Check content
if echo "$response_health" | grep -q "OK"; then
    echo "GET /health: Body 'OK' - PASSED"
else
    echo "GET /health: Body 'OK' - FAILED"
    exit 1
fi

# --- Test /foo Path (404) ---
echo -e "\nTesting GET /foo (404 Not Found)"
response_foo=$(curl -is http://localhost:8080/foo)
echo "$response_foo"

# Check status code
if echo "$response_foo" | grep -q "HTTP/1.1 404 Not Found"; then
    echo "GET /foo: Status 404 Not Found - PASSED"
else
    echo "GET /foo: Status 404 Not Found - FAILED"
    exit 1
fi

# Check content - updated expected message based on server.js
expected_404_msg="Not Found. This is a WebSocket server, or the path is incorrect."
if echo "$response_foo" | grep -q "$expected_404_msg"; then
    echo "GET /foo: Body '$expected_404_msg' - PASSED"
else
    echo "GET /foo: Body '$expected_404_msg' - FAILED"
    # For debugging, show what was actually received in the body
    echo "Actual body for /foo:"
    echo "$response_foo" | awk '/^\r?$/{p=1;next}p'
    exit 1
fi

# --- Test WebSocket Connection ---
echo -e "\nTesting WebSocket connection"

# Create a simple Node.js WebSocket client script
cat << EOF > ws_client_test.js
const WebSocket = require('ws');
const ws = new WebSocket('ws://localhost:8080');
let receivedClientId = false;

ws.on('open', function open() {
  console.log('Client: Connected to WebSocket server');
});

ws.on('message', function incoming(data) {
  console.log('Client: Received message');
  // MessageType (1 byte) + ClientID (64 bytes)
  // MessageType for CLIENT_ID_ANNOUNCEMENT is 0x01 (1)
  const EXPECTED_MESSAGE_TYPE = 1;
  const EXPECTED_CLIENT_ID_LENGTH = 64; // Must match CLIENT_ID_LENGTH in core.js
  const EXPECTED_TOTAL_LENGTH = 1 + EXPECTED_CLIENT_ID_LENGTH;

  if (data instanceof Buffer && data.length === EXPECTED_TOTAL_LENGTH && data.readUInt8(0) === EXPECTED_MESSAGE_TYPE) {
    const clientId = data.toString('utf8', 1, 1 + EXPECTED_CLIENT_ID_LENGTH);
    console.log('Client: Received Client ID:', clientId);
    // Further check if the clientId is plausible (e.g., correct length for hex string)
    if (clientId.length === EXPECTED_CLIENT_ID_LENGTH) {
        receivedClientId = true;
        console.log('Client: Client ID announcement received and seems valid.');
    } else {
        console.error('Client: Extracted client ID has incorrect length. Expected ' + EXPECTED_CLIENT_ID_LENGTH + ', got ' + clientId.length);
    }
  } else {
    let errorDetails = 'Client: Unexpected message for client ID announcement. Details:';
    if (!(data instanceof Buffer)) {
        errorDetails += ' Not a Buffer.';
    } else {
        errorDetails += ' Length=' + data.length + ' (expected ' + EXPECTED_TOTAL_LENGTH + ').';
        if (data.length > 0) {
            errorDetails += ' Type=' + data.readUInt8(0) + ' (expected ' + EXPECTED_MESSAGE_TYPE + ').';
        }
    }
    console.error(errorDetails);
  }
  ws.close();
});

ws.on('close', function close() {
  console.log('Client: Disconnected');
  if(receivedClientId) {
    process.exit(0); // Success
  } else {
    process.exit(1); // Failure
  }
});

ws.on('error', function error(err) {
  console.error('Client: WebSocket error:', err);
  process.exit(1); // Failure
});

// Timeout in case connection or message takes too long
setTimeout(() => {
    console.error("Client: Test timeout. Closing connection.");
    ws.terminate(); // Force close
    process.exit(1); // Failure
}, 5000); // 5 seconds timeout
EOF

# Run the WebSocket client test
node ws_client_test.js
ws_client_exit_code=$?

if [ $ws_client_exit_code -eq 0 ]; then
    echo "WebSocket test: PASSED"
else
    echo "WebSocket test: FAILED (Exit code: $ws_client_exit_code)"
    exit 1
fi

echo -e "\nAll tests PASSED"
exit 0
