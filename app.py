from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import my_pb2
import output_pb2
import json
from colorama import Fore, Style, init
import warnings
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import base64

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

init(autoreset=True)

app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})


# ============================================================
# GENERIC PROTOBUF DECODER (schema-free)
# ============================================================
def _read_varint(buf, pos):
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    return result, pos


def _parse_proto(buf, depth=0, max_depth=8):
    fields = {}
    pos = 0
    while pos < len(buf):
        try:
            tag, pos = _read_varint(buf, pos)
        except Exception:
            break
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 0:
            break
        try:
            if wire_type == 0:
                val, pos = _read_varint(buf, pos)
                fields.setdefault(field_num, []).append(("varint", val))
            elif wire_type == 1:
                if pos + 8 > len(buf):
                    break
                fields.setdefault(field_num, []).append(
                    ("fixed64", int.from_bytes(buf[pos:pos + 8], "little")))
                pos += 8
            elif wire_type == 2:
                length, pos = _read_varint(buf, pos)
                if pos + length > len(buf):
                    break
                val = buf[pos:pos + length]
                pos += length
                as_str = None
                try:
                    s = val.decode("utf-8")
                    if len(s) > 0 and all(c.isprintable() or c in "\r\n\t" for c in s):
                        as_str = s
                except Exception:
                    pass
                if as_str is not None:
                    fields.setdefault(field_num, []).append(("string", as_str))
                else:
                    nested = None
                    if depth < max_depth and len(val) > 0:
                        try:
                            nested = _parse_proto(val, depth + 1, max_depth)
                            if not nested:
                                nested = None
                        except Exception:
                            nested = None
                    if nested is not None:
                        fields.setdefault(field_num, []).append(("message", nested))
                    else:
                        fields.setdefault(field_num, []).append(("bytes", val.hex()))
            elif wire_type == 5:
                if pos + 4 > len(buf):
                    break
                fields.setdefault(field_num, []).append(
                    ("fixed32", int.from_bytes(buf[pos:pos + 4], "little")))
                pos += 4
            else:
                break
        except Exception:
            break
    return fields


def decode_major_login(raw: bytes):
    """Decode MajorLogin response. Format: [64-byte signature][protobuf]"""
    if not raw:
        return None

    offset = 64 if len(raw) > 64 else 0
    fields = _parse_proto(raw[offset:])

    def _has_jwt(fdict):
        return any(
            v[0] == "string" and v[1].startswith("eyJ")
            for vals in fdict.values() for v in vals
        )

    if fields and _has_jwt(fields):
        return {"offset": offset, "fields": fields}

    for off in range(0, min(128, len(raw))):
        f = _parse_proto(raw[off:])
        if f and _has_jwt(f):
            return {"offset": off, "fields": f}

    if fields:
        return {"offset": offset, "fields": fields}
    return None


# ============================================================
# EXACT OUTPUT FORMAT
# ============================================================
def build_login_result(raw, uid, open_id, platform_type, access_token=None):
    """
    Exact response format:
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
    decoded = decode_major_login(raw)
    if not decoded:
        return {
            "region": "N/A",
            "status": "N/A",
            "team": "TEAM_STAR",
            "token": "N/A",
            "token_access": access_token or "N/A",
            "uid": str(uid),
            "account_id": "N/A",
            "ServerUrl": ""
        }

    fields = decoded["fields"]

    def fget(num, kind=None):
        for v in fields.get(num, []):
            if kind is None or v[0] == kind:
                return v[1]
        return None

    account_id = fget(1, "varint")
    region = fget(2, "string") or fget(3, "string") or "N/A"
    status = fget(5, "string") or "N/A"          # environment: "live"
    token = fget(8, "string") or "N/A"
    server_url = fget(10, "string") or ""

    return {
        "region": region,
        "status": status,
        "team": "STAR_GMRR",
        "token": token,
        "token_access": access_token or "N/A",
        "uid": str(uid),
        "account_id": str(account_id) if account_id else "N/A",
        "ServerUrl": server_url,
    }


# ============================================================
# TOKEN / GAME DATA HELPERS
# ============================================================
def get_token(password, uid):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4 (Vivo Y15c; Android 12; en;IN;)",
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
            "User-Agent": "GarenaMSDK/4.0.19P4 (Vivo Y15c; Android 12; en;IN;)",
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
        "X-Ga-Sv": "1789534056",
        "Authorization": "Bearer ",
        "X-Ga": "v1 1",
        "ReleaseVersion": "OB55",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1"
    }


MAJOR_LOGIN_URL = "https://loginbp.ppmainecoonghj.com/MajorLogin"


def build_game_data(open_id, access_token, uid, platform_type):
    g = my_pb2.GameData()
    g.timestamp = "2025-05-29 13:11:47"
    g.game_name = "free fire"
    g.game_version = 1
    g.version_code = "1.132.2"
    g.os_info = "Android OS 11 / API-30 (RKQ1.201112.002/eng.realme.20221110.193122)"
    g.device_type = "Handheld"
    g.network_provider = "JIO"
    g.connection_type = "MOBILE"
    g.screen_width = 720
    g.screen_height = 1600
    g.dpi = "280"
    g.cpu_info = "ARM Cortex-A73 | 2200 | 4"
    g.total_ram = 4096
    g.gpu_name = "Adreno (TM) 610"
    g.gpu_version = "OpenGL ES 3.2"
    g.user_id = uid
    g.ip_address = "182.75.115.22"
    g.language = "en"
    g.open_id = open_id
    g.access_token = access_token
    g.platform_type = platform_type
    g.device_form_factor = "Handheld"
    g.device_model = "realme RMX1825"
    g.field_60 = 30000
    g.field_61 = 27500
    g.field_62 = 1940
    g.field_63 = 720
    g.field_64 = 28000
    g.field_65 = 30000
    g.field_66 = 28000
    g.field_67 = 30000
    g.field_70 = 4
    g.field_73 = 2
    g.library_path = "/data/app/com.dts.freefireth-XaT5M7jRwEL-nPaKOQvqdg==/lib/arm"
    g.field_76 = 1
    g.apk_info = "2f4a7f349f3a3ea581fc4d803bc5a977|/data/app/com.dts.freefireth-XaT5M7jRwEL-nPaKOQvqdg==/base.apk"
    g.field_78 = 6
    g.field_79 = 1
    g.os_architecture = "64"
    g.build_number = "2022041388"
    g.field_85 = 1
    g.graphics_backend = "OpenGLES3"
    g.max_texture_units = 16383
    g.rendering_api = 4
    g.encoded_field_89 = "\x10U\x15\x03\x02\t\rPYN\tEX\x03AZO9X\x07\rU\niZPVj\x05\rm\t\x04c"
    g.field_92 = 8999
    g.marketplace = "3rd_party"
    g.encryption_key = "Jp2DT7F3Is55K/92LSJ4PWkJxZnMzSNn+HEBK2AFBDBdrLpWTA3bZjtbU3JbXigkIFFJ5ZJKi0fpnlJCPDD2A7h2aPQ="
    g.total_storage = 64000
    g.field_97 = 1
    g.field_98 = 1
    g.field_99 = str(platform_type)
    g.field_100 = str(platform_type).encode()
    return g


# ============================================================
# CORE FLOWS
# ============================================================
def process_token(uid, password):
    token_data = get_token(password, uid)
    if not token_data:
        return {
            "region": "N/A",
            "status": "N/A",
            "team": "TEAM_STAR",
            "token": "N/A",
            "token_access": "N/A",
            "uid": str(uid),
            "account_id": "N/A",
            "ServerUrl": ""
        }

    access_token = token_data["access_token"]
    open_id = token_data["open_id"]

    game_data = build_game_data(
        open_id=open_id,
        access_token=access_token,
        uid=uid,
        platform_type=4
    )

    edata = encrypt_message(AES_KEY, AES_IV, game_data.SerializeToString())
    headers = build_login_headers()

    try:
        response = requests.post(MAJOR_LOGIN_URL, data=edata, headers=headers, verify=False, timeout=10)
        if response.status_code == 200:
            return build_login_result(
                response.content,
                uid=uid,
                open_id=open_id,
                platform_type=4,
                access_token=access_token
            )
        else:
            return {
                "region": "N/A",
                "status": "N/A",
                "team": "TEAM_STAR",
                "token": "N/A",
                "token_access": access_token,
                "uid": str(uid),
                "account_id": "N/A",
                "ServerUrl": "",
                "error": f"HTTP {response.status_code}: {response.text.strip()[:200]}"
            }
    except requests.RequestException as e:
        return {
            "region": "N/A",
            "status": "N/A",
            "team": "TEAM_STAR",
            "token": "N/A",
            "token_access": access_token,
            "uid": str(uid),
            "account_id": "N/A",
            "ServerUrl": "",
            "error": f"request failed: {e}"
        }


def process_access_token(access_token, uid=None, platform_type=4):
    token_data = get_token_inspect_data(access_token)
    if not token_data:
        return {
            "region": "N/A",
            "status": "N/A",
            "team": "TEAM_STAR",
            "token": "N/A",
            "token_access": access_token,
            "uid": str(uid) if uid else "N/A",
            "account_id": "N/A",
            "ServerUrl": "",
            "error": "INVALID_TOKEN"
        }

    open_id = token_data["open_id"]
    platform_type = token_data.get("platform", platform_type)
    uid = uid or str(token_data["uid"])

    game_data = build_game_data(
        open_id=open_id,
        access_token=access_token,
        uid=uid,
        platform_type=platform_type
    )

    edata = encrypt_message(AES_KEY, AES_IV, game_data.SerializeToString())
    headers = build_login_headers()

    try:
        response = requests.post(MAJOR_LOGIN_URL, data=edata, headers=headers, verify=False, timeout=10)
        if response.status_code == 200:
            return build_login_result(
                response.content,
                uid=uid,
                open_id=open_id,
                platform_type=platform_type,
                access_token=access_token
            )
        else:
            error_text = response.text.strip()
            msg = "unknown error"
            if error_text == "BR_PLATFORM_INVALID_PLATFORM":
                msg = "this account is registered on another platform"
            elif error_text == "BR_GOP_TOKEN_AUTH_FAILED":
                msg = "AccessToken invalid."
            elif error_text == "BR_PLATFORM_INVALID_OPENID":
                msg = "OpenID invalid."
            return {
                "region": "N/A",
                "status": "N/A",
                "team": "TEAM_STAR",
                "token": "N/A",
                "token_access": access_token,
                "uid": str(uid),
                "account_id": "N/A",
                "ServerUrl": "",
                "error": msg
            }
    except requests.RequestException as e:
        return {
            "region": "N/A",
            "status": "N/A",
            "team": "TEAM_STAR",
            "token": "N/A",
            "token_access": access_token,
            "uid": str(uid),
            "account_id": "N/A",
            "ServerUrl": "",
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