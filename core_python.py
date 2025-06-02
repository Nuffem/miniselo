import os
import hashlib
import struct

# Constants
MESSAGE_TYPES = {
    'CLIENT_ID_ANNOUNCEMENT': 0,
    'FORWARDED_MESSAGE': 1,
    'ERROR_MESSAGE': 2,
    'MESSAGE_TO_FORWARD': 3,  # Added for decoding client messages
}

ERROR_CODES = {
    'INVALID_MESSAGE_FORMAT': 0,
    'INVALID_RECIPIENT_ID': 1,
    'CLIENT_ID_ALREADY_TAKEN': 2,
    'ORIGIN_NOT_ALLOWED': 3,
    'UNKNOWN_ERROR': 4,
    'INVALID_CLIENT_ID_LENGTH': 5,
    'INVALID_SENDER_ID_LENGTH': 6,
    'MESSAGE_TOO_LONG': 7,
    'UNKNOWN_MESSAGE_TYPE': 8,
}

CLIENT_ID_LENGTH = 64  # SHA-256 hex string length

# Functions
def generate_secure_key() -> bytes:
    """Generates 32 random bytes."""
    return os.urandom(32)

def calculate_client_id(key: bytes, origin: str) -> str:
    """
    Calculates the client ID by hashing the key and origin.
    """
    combined = key + origin.encode('utf-8')
    hashed = hashlib.sha256(combined).hexdigest()
    return hashed

def encode_client_id_announcement(client_id_string: str) -> bytes:
    """
    Encodes a client ID announcement message.
    Format: MESSAGE_TYPES['CLIENT_ID_ANNOUNCEMENT'] (1 byte) + client_id_string (UTF-8 encoded, 64 bytes).
    """
    if len(client_id_string) != CLIENT_ID_LENGTH:
        raise ValueError(f"Client ID string must be {CLIENT_ID_LENGTH} characters long.")
    message_type_byte = struct.pack('>B', MESSAGE_TYPES['CLIENT_ID_ANNOUNCEMENT'])
    client_id_bytes = client_id_string.encode('utf-8')
    return message_type_byte + client_id_bytes

def encode_forwarded_message(sender_id_string: str, message_string: str) -> bytes:
    """
    Encodes a forwarded message.
    Format: MESSAGE_TYPES['FORWARDED_MESSAGE'] (1 byte) + sender_id_string (UTF-8 encoded, 64 bytes) +
            len(message_string_bytes) (2 bytes, big-endian) + message_string (UTF-8 encoded).
    """
    if len(sender_id_string) != CLIENT_ID_LENGTH:
        raise ValueError(f"Sender ID string must be {CLIENT_ID_LENGTH} characters long.")
    
    message_type_byte = struct.pack('>B', MESSAGE_TYPES['FORWARDED_MESSAGE'])
    sender_id_bytes = sender_id_string.encode('utf-8')
    message_bytes = message_string.encode('utf-8')
    message_length_bytes = struct.pack('>H', len(message_bytes))
    
    if len(message_bytes) > 65535: # Max length for uint16
        raise ValueError("Message string is too long.")

    return message_type_byte + sender_id_bytes + message_length_bytes + message_bytes

def encode_error_message(error_code: int, error_message_string: str) -> bytes:
    """
    Encodes an error message.
    Format: MESSAGE_TYPES['ERROR_MESSAGE'] (1 byte) + error_code (1 byte) +
            len(error_message_string_bytes) (2 bytes, big-endian) + error_message_string (UTF-8 encoded).
    """
    message_type_byte = struct.pack('>B', MESSAGE_TYPES['ERROR_MESSAGE'])
    error_code_byte = struct.pack('>B', error_code)
    error_message_bytes = error_message_string.encode('utf-8')
    error_message_length_bytes = struct.pack('>H', len(error_message_bytes))

    if len(error_message_bytes) > 65535: # Max length for uint16
        raise ValueError("Error message string is too long.")

    return message_type_byte + error_code_byte + error_message_length_bytes + error_message_bytes

def decode_message_from_client(binary_message: bytes) -> dict:
    """
    Decodes a message received from a client.
    Expected format for MESSAGE_TO_FORWARD:
        MessageType (1 byte) + RecipientID (64 bytes, UTF-8 string) +
        PayloadLength (2 bytes, big-endian) + Payload (UTF-8 string).
    Returns a dictionary representing the parsed message or an error.
    """
    if not binary_message:
        return {'type': MESSAGE_TYPES['ERROR_MESSAGE'], 'code': ERROR_CODES['INVALID_MESSAGE_FORMAT'], 'error': 'Empty message received.'}

    try:
        message_type = binary_message[0]

        if message_type == MESSAGE_TYPES['MESSAGE_TO_FORWARD']:
            if len(binary_message) < 1 + CLIENT_ID_LENGTH + 2:
                return {'type': MESSAGE_TYPES['ERROR_MESSAGE'], 'code': ERROR_CODES['INVALID_MESSAGE_FORMAT'], 'error': 'Message too short for MESSAGE_TO_FORWARD.'}

            recipient_id_bytes = binary_message[1 : 1 + CLIENT_ID_LENGTH]
            recipient_id = recipient_id_bytes.decode('utf-8')

            if len(recipient_id) != CLIENT_ID_LENGTH: # Should already be guaranteed by slicing, but good for robustness
                 return {'type': MESSAGE_TYPES['ERROR_MESSAGE'], 'code': ERROR_CODES['INVALID_MESSAGE_FORMAT'], 'error': f'Recipient ID has invalid length. Expected {CLIENT_ID_LENGTH}.'}


            payload_length_bytes = binary_message[1 + CLIENT_ID_LENGTH : 1 + CLIENT_ID_LENGTH + 2]
            payload_length = struct.unpack('>H', payload_length_bytes)[0]

            payload_start_index = 1 + CLIENT_ID_LENGTH + 2
            if len(binary_message) < payload_start_index + payload_length:
                return {'type': MESSAGE_TYPES['ERROR_MESSAGE'], 'code': ERROR_CODES['INVALID_MESSAGE_FORMAT'], 'error': 'Message payload shorter than specified length.'}
            
            payload_bytes = binary_message[payload_start_index : payload_start_index + payload_length]
            payload = payload_bytes.decode('utf-8')

            return {
                'type': MESSAGE_TYPES['MESSAGE_TO_FORWARD'],
                'recipient_id': recipient_id,
                'message': payload
            }
        else:
            return {'type': MESSAGE_TYPES['ERROR_MESSAGE'], 'code': ERROR_CODES['UNKNOWN_MESSAGE_TYPE'], 'error': f'Unknown message type: {message_type}'}

    except UnicodeDecodeError:
        return {'type': MESSAGE_TYPES['ERROR_MESSAGE'], 'code': ERROR_CODES['INVALID_MESSAGE_FORMAT'], 'error': 'Failed to decode UTF-8 string.'}
    except struct.error:
        return {'type': MESSAGE_TYPES['ERROR_MESSAGE'], 'code': ERROR_CODES['INVALID_MESSAGE_FORMAT'], 'error': 'Failed to unpack message structure (e.g., length fields).'}
    except Exception as e:
        # General catch-all for other unexpected parsing errors
        return {'type': MESSAGE_TYPES['ERROR_MESSAGE'], 'code': ERROR_CODES['UNKNOWN_ERROR'], 'error': f'An unexpected error occurred during message decoding: {str(e)}'}

if __name__ == '__main__':
    # Example Usage and Basic Tests (can be expanded)
    print("Running basic tests for core_python.py...")

    # Test generate_secure_key
    key1 = generate_secure_key()
    key2 = generate_secure_key()
    assert len(key1) == 32, "generate_secure_key length is incorrect"
    assert key1 != key2, "generate_secure_key should produce different keys"
    print("generate_secure_key: OK")

    # Test calculate_client_id
    test_key = b'test_key_1234567890123456789012' # 32 bytes
    test_origin = "https://example.com"
    client_id = calculate_client_id(test_key, test_origin)
    assert len(client_id) == CLIENT_ID_LENGTH, "calculate_client_id length is incorrect"
    print(f"calculate_client_id (example): {client_id}")
    # Re-calculate with same inputs should yield same ID
    client_id_again = calculate_client_id(test_key, test_origin)
    assert client_id == client_id_again, "calculate_client_id is not deterministic"
    print("calculate_client_id: OK")

    # Test encode_client_id_announcement
    try:
        encoded_announce = encode_client_id_announcement(client_id)
        assert encoded_announce[0] == MESSAGE_TYPES['CLIENT_ID_ANNOUNCEMENT'], "encode_client_id_announcement type byte failed"
        assert encoded_announce[1:].decode('utf-8') == client_id, "encode_client_id_announcement client_id mismatch"
        print("encode_client_id_announcement: OK")
    except Exception as e:
        print(f"encode_client_id_announcement ERROR: {e}")

    try:
        encode_client_id_announcement("short_id") # Should fail
        print("encode_client_id_announcement ERROR: Did not raise error for short ID.")
    except ValueError:
        print("encode_client_id_announcement (short ID check): OK (raised ValueError as expected)")


    # Test encode_forwarded_message
    sender_id = client_id # Use the one generated above
    message_content = "Hello, this is a test message!"
    try:
        encoded_forward = encode_forwarded_message(sender_id, message_content)
        assert encoded_forward[0] == MESSAGE_TYPES['FORWARDED_MESSAGE'], "encode_forwarded_message type byte failed"
        assert encoded_forward[1:1+CLIENT_ID_LENGTH].decode('utf-8') == sender_id, "encode_forwarded_message sender_id mismatch"
        msg_len_from_bytes = struct.unpack('>H', encoded_forward[1+CLIENT_ID_LENGTH : 1+CLIENT_ID_LENGTH+2])[0]
        assert msg_len_from_bytes == len(message_content.encode('utf-8')), "encode_forwarded_message length field mismatch"
        assert encoded_forward[1+CLIENT_ID_LENGTH+2:].decode('utf-8') == message_content, "encode_forwarded_message content mismatch"
        print("encode_forwarded_message: OK")
    except Exception as e:
        print(f"encode_forwarded_message ERROR: {e}")

    # Test encode_error_message
    error_code_val = ERROR_CODES['INVALID_MESSAGE_FORMAT']
    error_message_val = "The message format was invalid."
    try:
        encoded_error = encode_error_message(error_code_val, error_message_val)
        assert encoded_error[0] == MESSAGE_TYPES['ERROR_MESSAGE'], "encode_error_message type byte failed"
        assert encoded_error[1] == error_code_val, "encode_error_message error code mismatch"
        err_msg_len_from_bytes = struct.unpack('>H', encoded_error[2:4])[0]
        assert err_msg_len_from_bytes == len(error_message_val.encode('utf-8')), "encode_error_message length field mismatch"
        assert encoded_error[4:].decode('utf-8') == error_message_val, "encode_error_message content mismatch"
        print("encode_error_message: OK")
    except Exception as e:
        print(f"encode_error_message ERROR: {e}")

    # Test decode_message_from_client (MESSAGE_TO_FORWARD)
    recipient_id = client_id # Use a valid client_id for testing
    payload_to_send = "This is a payload to be forwarded."
    
    # Construct a valid MESSAGE_TO_FORWARD binary message
    msg_to_fwd_type_byte = struct.pack('>B', MESSAGE_TYPES['MESSAGE_TO_FORWARD'])
    recipient_id_bytes = recipient_id.encode('utf-8')
    payload_bytes_to_send = payload_to_send.encode('utf-8')
    payload_len_bytes_to_send = struct.pack('>H', len(payload_bytes_to_send))
    
    valid_binary_msg_to_fwd = msg_to_fwd_type_byte + recipient_id_bytes + payload_len_bytes_to_send + payload_bytes_to_send
    
    decoded_msg = decode_message_from_client(valid_binary_msg_to_fwd)
    print(f"Decoded (valid MESSAGE_TO_FORWARD): {decoded_msg}")
    assert decoded_msg['type'] == MESSAGE_TYPES['MESSAGE_TO_FORWARD'], "decode_message_from_client (valid) type mismatch"
    assert decoded_msg['recipient_id'] == recipient_id, "decode_message_from_client (valid) recipient_id mismatch"
    assert decoded_msg['message'] == payload_to_send, "decode_message_from_client (valid) message mismatch"
    print("decode_message_from_client (MESSAGE_TO_FORWARD): OK")

    # Test decode_message_from_client (Unknown type)
    unknown_type_msg = b'\x99' + recipient_id_bytes + payload_len_bytes_to_send + payload_bytes_to_send # Type 0x99 is not defined
    decoded_unknown = decode_message_from_client(unknown_type_msg)
    print(f"Decoded (unknown type): {decoded_unknown}")
    assert decoded_unknown['type'] == MESSAGE_TYPES['ERROR_MESSAGE'], "decode_message_from_client (unknown type) error type mismatch"
    assert decoded_unknown['code'] == ERROR_CODES['UNKNOWN_MESSAGE_TYPE'], "decode_message_from_client (unknown type) error code mismatch"
    print("decode_message_from_client (Unknown Message Type): OK")

    # Test decode_message_from_client (Too short)
    too_short_msg = msg_to_fwd_type_byte + recipient_id_bytes[:10] # Truncated recipient ID
    decoded_short = decode_message_from_client(too_short_msg)
    print(f"Decoded (too short): {decoded_short}")
    assert decoded_short['type'] == MESSAGE_TYPES['ERROR_MESSAGE'], "decode_message_from_client (too short) error type mismatch"
    assert decoded_short['code'] == ERROR_CODES['INVALID_MESSAGE_FORMAT'], "decode_message_from_client (too short) error code mismatch"
    print("decode_message_from_client (Too Short): OK")

    # Test decode_message_from_client (Payload length mismatch - too short)
    incorrect_payload_len_msg = msg_to_fwd_type_byte + recipient_id_bytes + struct.pack('>H', len(payload_bytes_to_send) + 5) + payload_bytes_to_send
    decoded_payload_mismatch = decode_message_from_client(incorrect_payload_len_msg)
    print(f"Decoded (payload length mismatch): {decoded_payload_mismatch}")
    assert decoded_payload_mismatch['type'] == MESSAGE_TYPES['ERROR_MESSAGE'], "decode_message_from_client (payload length mismatch) error type mismatch"
    assert decoded_payload_mismatch['code'] == ERROR_CODES['INVALID_MESSAGE_FORMAT'], "decode_message_from_client (payload length mismatch) error code mismatch"
    print("decode_message_from_client (Payload Length Mismatch): OK")

    print("Basic tests for core_python.py finished.")
