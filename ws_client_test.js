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
