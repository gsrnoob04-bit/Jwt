from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
from colorama import Fore, Style, init
import warnings
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed
from google.protobuf import json_format
import time
import base64

import FreeFire_pb2

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'

init(autoreset=True)

app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})


# ============================================================
# PROTOBUF FINDER
# ============================================================
def find_protobuf_start(data: bytes) -> int:
    """LoginRes protobuf hamesha field markers ke saath start hota hai."""
    # Method 1: "IND" pattern
    idx = data.find(b'\x12\x03IND')
    if idx != -1:
        for i in range(idx - 1, max(idx - 20, -1), -1):
            if data[i] == 0x08:
                return i

    # Method 2: JWT ke just pehle wala field marker
    jwt_marker = data.find(b'B\xe7\x05eyJ')
    if jwt_marker != -1:
        for i in range(jwt_marker - 1, max(jwt_marker - 200, -1), -1):
            if data[i] == 0x08:
                return i

    # Method 3: Fallback
    return data.find(b'\x08')


# ============================================================
# EXACT OUTPUT FORMAT (आपका पुराना)
# ============================================================
def build_login_result(raw, uid, open_id, platform_type, access_token=None):
    """
    Output format:
    {
      "region": "IND",
      "status": "live",
      "team": "STAR_GMRR",
      "token": "eyJ...",
      "token_access": "3f3d...",
      "uid": "4561074788",
      "account_id": "14854730454",
      "ServerUrl": ""
    }
    """
    out = {
        "region": "N/A",
        "status": "N/A",
        "team": "STAR_GMRR",
        "token": "N/A",
        "token_access": access_token or "N/A",
        "uid": str(uid),
        "account_id": "N/A",
        "ServerUrl": "",
    }

    if not raw:
        return out

    start_idx = find_protobuf_start(raw)
    if start_idx == -1:
        return out

    proto_data = raw[start_idx:]

    try:
        msg = FreeFire_pb2.LoginRes()
        msg.ParseFromString(proto_data)
        m = json.loads(json_format.MessageToJson(msg))

        out["token"]      = m.get("token") or "N/A"
        out["region"]     = m.get("notiRegion") or m.get("lockRegion") or "N/A"
        out["status"]     = m.get("agoraEnvironment") or "live"
        out["account_id"] = str(m.get("accountId") or "N/A")
        out["ServerUrl"]  = m.get("serverUrl") or ""
    except Exception as e:
        print(Fore.RED + f"LoginRes parse failed: {e}")

    # Fallback: JWT regex
    if out["token"] == "N/A":
        import re
        text = raw.decode("utf-8", errors="ignore")
        found = re.search(
            r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", text
        )
        if found:
            out["token"] = found.group(0)

    return out


# ============================================================
# TOKEN / LOGIN HELPERS
# ============================================================
def get_token(password, uid):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P9(A063 ;Android 13;en;IN;)",   # ✅ अपडेटेड
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    response = requests.post(url, headers=headers, data=data, verify=False, timeout=10)
    if response.status_code != 200:
        print(Fore.RED + f"Failed to retrieve token for UID {uid}: {response.text}")
        return None
    return response.json()


def get_token_inspect_data(access_token):
    try:
        url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
        headers = {
            "User-Agent": "GarenaMSDK/4.0.19P9(A063 ;Android 13;en;IN;)",   # ✅ अपडेटेड
            "Connection": "close"
        }
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if 'open_id' in data and 'platform' in data and 'uid' in data:
                return data
    except Exception as e:
        print(Fore.RED + f"Error inspecting token: {e}")
    return None


def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)


def load_tokens(file_path, limit=None):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            tokens = list(data.items())
            if limit is not None:
                tokens = tokens[:limit]
            return tokens
    except Exception as e:
        print(Fore.RED + f"Failed to load tokens: {e}")
        return []


def build_login_headers():
    return {
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-Ga-Sv": str(int(time.time())),              # ✅ डायनामिक
        "Authorization": "Bearer",
        "X-Ga": "v1 1",
        "Releaseversion": "OB55",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
        "PlAy_VeR": "1.132.1",                          # ✅ नया
        "Ob_VeR": "OB55",                               # ✅ नया
    }


MAJOR_LOGIN_URL = "https://loginbp.ppmainecoonghj.com/MajorLogin"


def build_login_req(open_id, access_token):
    """Simple LoginReq protobuf — working approach"""
    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": access_token,
        "orign_platform_type": "4"
    })
    proto = FreeFire_pb2.LoginReq()
    json_format.ParseDict(json.loads(body), proto)
    return proto.SerializeToString()


# ============================================================
# CORE FLOWS
# ============================================================
def process_token(uid, password):
    token_data = get_token(password, uid)
    if not token_data:
        return {
            "region": "N/A", "status": "N/A", "team": "STAR_GMRR",
            "token": "N/A", "token_access": "N/A",
            "uid": str(uid), "account_id": "N/A", "ServerUrl": ""
        }

    access_token = token_data["access_token"]
    open_id = token_data["open_id"]

    proto_bytes = build_login_req(open_id, access_token)
    edata = encrypt_message(AES_KEY, AES_IV, proto_bytes)
    headers = build_login_headers()

    try:
        response = requests.post(MAJOR_LOGIN_URL, data=edata,
                                 headers=headers, verify=False, timeout=10)
        if response.status_code == 200:
            return build_login_result(
                response.content, uid=uid, open_id=open_id,
                platform_type=4, access_token=access_token
            )
        else:
            return {
                "region": "N/A", "status": "N/A", "team": "STAR_GMRR",
                "token": "N/A", "token_access": access_token,
                "uid": str(uid), "account_id": "N/A", "ServerUrl": "",
                "error": f"HTTP {response.status_code}: {response.text.strip()[:200]}"
            }
    except requests.RequestException as e:
        return {
            "region": "N/A", "status": "N/A", "team": "STAR_GMRR",
            "token": "N/A", "token_access": access_token,
            "uid": str(uid), "account_id": "N/A", "ServerUrl": "",
            "error": f"request failed: {e}"
        }


def process_access_token(access_token, uid=None, platform_type=4):
    token_data = get_token_inspect_data(access_token)
    if not token_data:
        return {
            "region": "N/A", "status": "N/A", "team": "STAR_GMRR",
            "token": "N/A", "token_access": access_token,
            "uid": str(uid) if uid else "N/A",
            "account_id": "N/A", "ServerUrl": "",
            "error": "INVALID_TOKEN"
        }

    open_id = token_data["open_id"]
    platform_type = token_data.get("platform", platform_type)
    uid = uid or str(token_data["uid"])

    proto_bytes = build_login_req(open_id, access_token)
    edata = encrypt_message(AES_KEY, AES_IV, proto_bytes)
    headers = build_login_headers()

    try:
        response = requests.post(MAJOR_LOGIN_URL, data=edata,
                                 headers=headers, verify=False, timeout=10)
        if response.status_code == 200:
            return build_login_result(
                response.content, uid=uid, open_id=open_id,
                platform_type=platform_type, access_token=access_token
            )
        else:
            error_text = response.text.strip()
            msg = "unknown error"
            if "BR_PLATFORM_INVALID_PLATFORM" in error_text:
                msg = "this account is registered on another platform"
            elif "BR_GOP_TOKEN_AUTH_FAILED" in error_text:
                msg = "AccessToken invalid."
            elif "BR_PLATFORM_INVALID_OPENID" in error_text:
                msg = "OpenID invalid."
            elif "BR_AUTH_ABNORMAL_GAME_CLIENT" in error_text:
                msg = "abnormal game client detected"
            return {
                "region": "N/A", "status": "N/A", "team": "STAR_GMRR",
                "token": "N/A", "token_access": access_token,
                "uid": str(uid), "account_id": "N/A", "ServerUrl": "",
                "error": msg
            }
    except requests.RequestException as e:
        return {
            "region": "N/A", "status": "N/A", "team": "STAR_GMRR",
            "token": "N/A", "token_access": access_token,
            "uid": str(uid), "account_id": "N/A", "ServerUrl": "",
            "error": f"request failed: {e}"
        }


# ============================================================
# ROUTES
# ============================================================
@app.route('/token', methods=['GET'])
def get_responses():
    access_token = request.args.get('access_token')
    if access_token:
        cache_key = f"at_{access_token}_{int(time.time())}"
        cached = cache.get(cache_key)
        if cached:
            return jsonify(cached)
        response = process_access_token(access_token)
        cache.set(cache_key, response, timeout=25200)
        return jsonify(response)

    uid = request.args.get('uid')
    password = request.args.get('password')

    if uid and password:
        cache_key = f"tok_{uid}_{password}_{int(time.time())}"
        cached = cache.get(cache_key)
        if cached:
            return jsonify(cached)
        response = process_token(uid, password)
        cache.set(cache_key, response, timeout=25200)
        return jsonify(response)

    limit = request.args.get('limit', default=500, type=int)
    tokens = load_tokens("accs.txt", limit)
    responses = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_uid = {executor.submit(process_token, uid, password): uid for uid, password in tokens}
        for future in as_completed(future_to_uid):
            try:
                responses.append(future.result())
                time.sleep(1)
            except Exception as e:
                responses.append({"uid": future_to_uid[future], "error": str(e)})

    token_list = [item['token'] for item in responses if item.get('token') and item['token'] != 'N/A']
    return jsonify({"tokens": token_list})


@app.route('/api/get_jwt', methods=['GET'])
def get_jwt():
    access_token = request.args.get('access_token')
    guest_uid = request.args.get('guest_uid')
    guest_password = request.args.get('guest_password')

    if access_token:
        response = process_access_token(access_token)
        if response.get('token') and response['token'] != 'N/A':
            return jsonify({"success": True, "BearerAuth": response['token']})
        return jsonify({
            "success": False,
            "message": response.get('error', 'INVALID_TOKEN')
        }), 400

    elif guest_uid and guest_password:
        response = process_token(guest_uid, guest_password)
        if response.get('token') and response['token'] != 'N/A':
            return jsonify({"success": True, "BearerAuth": response['token']})
        return jsonify({
            "success": False,
            "message": "unregistered or banned account.",
            "detail": response.get('error', 'jwt not found in response.')
        }), 500

    return jsonify({
        "success": False,
        "message": "missing access_token (or guest_uid + guest_password)"
    }), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5030)