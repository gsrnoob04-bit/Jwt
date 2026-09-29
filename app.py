import time
import httpx
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64
import FreeFire_pb2

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB55"
USERAGENT = "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"
LOGIN_URL = "https://loginbp.ppmainecoonghj.com/"
CLIENT_URL = "https://clientbp.ppmainecoonghj.com/"

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    with httpx.Client() as client:
        resp = client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

def find_protobuf_start(data: bytes) -> int:
    """
    LoginRes protobuf hamesha field markers ke saath start hota hai.
    Hum response me se woh index dhoondhte hain jahan se valid protobuf start hota hai.
    Common markers: 
      - \x08 (field 1 varint - accountId ya similar)
      - \x12\x03IND pattern (region field)
    """
    # Method 1: "IND" pattern dhoondo (region field ke saath aata hai)
    # \x12\x03IND = field 2 (string, len 3), "IND"
    idx = data.find(b'\x12\x03IND')
    if idx != -1:
        # \x12 se pehle \x08 (field 1) hota hai — wahan se start karo
        # \x08 wala byte dhoondo idx se pehle
        for i in range(idx - 1, max(idx - 20, -1), -1):
            if data[i] == 0x08:
                return i

    # Method 2: JWT token ke just pehle wala protobuf field (B\xe7\x05) dhoondo
    jwt_marker = data.find(b'B\xe7\x05eyJ')
    if jwt_marker != -1:
        # Usse pehle \x08 dhoondo
        for i in range(jwt_marker - 1, max(jwt_marker - 200, -1), -1):
            if data[i] == 0x08:
                return i

    # Method 3: Fallback — pehla \x08 dhoondo
    return data.find(b'\x08')

def generate_jwt_token(uid: str, password: str):
    # Create account string from UID and password
    account = f"uid={uid}&password={password}"

    # Get access token and open_id
    token_val, open_id = get_access_token(account)

    if token_val == "0" or open_id == "0":
        raise Exception("Invalid UID or Password — access token not received")

    # Prepare login request
    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": "4"
    })

    # Convert to protobuf and encrypt
    proto_bytes = json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    # Send login request
    url = f"{LOGIN_URL}MajorLogin"
    headers = {
        'User-Agent': USERAGENT,
        'Accept': "*/*",
        'Accept-Encoding': "deflate, gzip",
        'X-Ga-Sv': "1789534056",
        'Authorization': "Bearer",
        'X-Ga': "v1 1",
        'Releaseversion': RELEASEVERSION,
        'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': "2018.4.12f1",
        'PlAy_VeR': "1.132.1",
        'Ob_VeR': RELEASEVERSION
    }

    with httpx.Client() as client:
        resp = client.post(url, data=payload, headers=headers)

        print(f"=== HTTP {resp.status_code} | Content-Length: {len(resp.content)} ===")

        # === Protobuf ka correct start dhoondo ===
        start_idx = find_protobuf_start(resp.content)

        if start_idx == -1:
            raise Exception(
                f"Protobuf start not found. Raw: {resp.content[:300]}"
            )

        proto_data = resp.content[start_idx:]
        print(f"=== Protobuf starts at index {start_idx} ===")
        print(f"=== Proto data (first 200 bytes): {proto_data[:200]} ===")

        # Parse protobuf
        try:
            msg = json.loads(json_format.MessageToJson(
                decode_protobuf(proto_data, FreeFire_pb2.LoginRes)
            ))
        except Exception as parse_err:
            raise Exception(
                f"Failed to parse LoginRes from index {start_idx}. "
                f"Raw (from start): {resp.content[start_idx:start_idx+300]}. "
                f"Error: {parse_err}"
            )

        # Prepare response
        response_data = {
            "account_Id": msg.get("accountId", ""),
            "agoraEnvironment": msg.get("agoraEnvironment", "live"),
            "ipRegion": msg.get("ipRegion", ""),
            "lockRegion": msg.get("lockRegion", ""),
            "region": msg.get("notiRegion", ""),
            "serverUrl": msg.get("serverUrl", ""),
            "token": f"{msg.get('token', '')}"
        }

        return response_data

# === Flask Routes ===
@app.route('/token', methods=['GET'])
def get_jwt_token():
    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify({"error": "Both uid and password parameters are required"}), 400

    try:
        token_data = generate_jwt_token(uid, password)
        return jsonify(token_data), 200
    except Exception as e:
        return jsonify({"error": f"Failed to generate token: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
