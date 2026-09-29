#!/usr/bin/env python3
"""
JWT Generator API - @DGDRIFT 
  /health
"""
import os
import re
import time
import json
import base64
import logging
import traceback

import requests
from flask import Flask, jsonify, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from urllib3.exceptions import InsecureRequestWarning

import my_pb2
import output_pb2

import warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# ==================== SETUP ====================
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
log = logging.getLogger("jwt-api")

app = Flask(__name__)

# ==================== CONSTANTS ====================
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'

OAUTH_URL       = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
MAJOR_LOGIN_URL = "https://loginbp.ppmainecoonghj.com/MajorLogin"

_token_cache        = {}   # {uid:password -> oauth_json}
_access_jwt_cache   = {}   # {access_token:open_id -> jwt_response}

# ==================== DEVELOPER INFO ====================
DEVELOPER   = "@DGDRIFT"
TELEGRAM    = "@DG_DRIFT"
OB_VERSION  = "OB55"
CLIENT_VER  = "1.132.8"
PLATFORM    = 8

# ==================== REGION NORMALIZER ====================
REGION_MAP = {
    "IN": "IND", "INDIA": "IND",
    "BRAZIL": "BR",
    "SINGAPORE": "SG",
    "INDONESIA": "ID",
    "THAILAND": "TH",
    "VIETNAM": "VN",
    "MENA": "ME",
    "PAKISTAN": "PK",
    "BANGLADESH": "BD",
    "MALAYSIA": "MY",
    "PHILIPPINES": "PH",
    "RUSSIA": "RU",
    "MEXICO": "MX",
    "USA": "US", "UNITED STATES": "US",
    "EUROPE": "EU",
    "EGYPT": "EG",
    "SAUDI": "SA", "SAUDI ARABIA": "SA",
    "TURKEY": "TR",
    "TAIWAN": "TW",
    "KOREA": "KR", "SOUTH KOREA": "KR",
    "JAPAN": "JP",
    "COLOMBIA": "CO",
    "ARGENTINA": "AR",
    "CHILE": "CL",
    "PERU": "PE",
}

def normalize_region(r):
    if not r:
        return None
    r = str(r).strip().upper()
    return REGION_MAP.get(r, r)

# ==================== REGION → SERVER URL ====================
REGION_URL = {
    "IND": "client.ind.freefiremobile.com",
    "BR":  "client.br.freefiremobile.com",
    "SG":  "client.sg.freefiremobile.com",
    "ID":  "client.id.freefiremobile.com",
    "TH":  "client.th.freefiremobile.com",
    "VN":  "client.vn.freefiremobile.com",
    "ME":  "client.me.freefiremobile.com",
    "PK":  "client.pk.freefiremobile.com",
    "BD":  "client.bd.freefiremobile.com",
    "MY":  "client.my.freefiremobile.com",
    "PH":  "client.ph.freefiremobile.com",
    "RU":  "client.ru.freefiremobile.com",
    "MX":  "client.mx.freefiremobile.com",
    "US":  "client.us.freefiremobile.com",
    "EU":  "client.eu.freefiremobile.com",
    "EG":  "client.eg.freefiremobile.com",
    "SA":  "client.sa.freefiremobile.com",
    "TR":  "client.tr.freefiremobile.com",
    "TW":  "client.tw.freefiremobile.com",
    "KR":  "client.kr.freefiremobile.com",
    "JP":  "client.jp.freefiremobile.com",
    "CO":  "client.co.freefiremobile.com",
    "AR":  "client.ar.freefiremobile.com",
    "CL":  "client.cl.freefiremobile.com",
    "PE":  "client.pe.freefiremobile.com",
}

def region_to_url(region):
    if not region:
        return "N/A"
    region = str(region).upper()
    url = REGION_URL.get(region)
    if url:
        return f"https://{url}"
    return f"https://client.{region.lower()}.freefiremobile.com"

# ==================== OAUTH ====================
def get_token(password, uid):
    key = f"{uid}:{password}"
    if key in _token_cache:
        return _token_cache[key]

    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P9(A063 ;Android 13;en;IN;)",   # ✅ अपडेटेड
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067",
    }
    try:
        res = requests.post(OAUTH_URL, headers=headers, data=data,
                            timeout=15, verify=False)
        if res.status_code != 200:
            log.warning(f"OAuth HTTP {res.status_code}: {res.text[:150]}")
            return None
        j = res.json()
        if "access_token" in j and "open_id" in j:
            _token_cache[key] = j
            return j
        log.warning(f"OAuth missing fields: {j}")
        return None
    except Exception as e:
        log.error(f"OAuth error: {e}")
        return None

# ==================== CRYPTO ====================
def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def decrypt_message(key, iv, ciphertext):
    if not ciphertext or len(ciphertext) % 16 != 0:
        return ciphertext
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)
    except Exception:
        return ciphertext

# ==================== JWT HELPERS ====================
def _decode_jwt_payload(token):
    if not token or token == "N/A":
        return {}
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        p = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception as e:
        log.debug(f"JWT decode failed: {e}")
        return {}


def _extract_open_id_from_token(token):
    """Access token khud JWT ho toh open_id nikaalo."""
    if not token:
        return None
    payload = _decode_jwt_payload(token)
    if not payload:
        return None
    return (payload.get("open_id")
            or payload.get("sub")
            or payload.get("uid")
            or payload.get("external_id"))


def _fill_from_jwt(out):
    if not out.get("token"):
        return out
    payload = _decode_jwt_payload(out["token"])
    if not payload:
        return out

    if not out.get("region"):
        r = (payload.get("lock_region")
             or payload.get("noti_region")
             or payload.get("region"))
        out["region"] = normalize_region(r)

    if not out.get("account_id"):
        out["account_id"] = payload.get("account_id")

    if not out.get("nickname"):
        out["nickname"] = payload.get("nickname")

    if not out.get("status"):
        out["status"] = "live"

    return out

# ==================== PROTOBUF PARSE ====================
def parse_garena_response(raw_bytes):
    out = {"token": None, "region": None, "status": None,
           "account_id": None, "nickname": None}

    # 1. Raw protobuf
    try:
        msg = output_pb2.Momin()
        msg.ParseFromString(raw_bytes)
        if msg.token:      out["token"] = msg.token
        if msg.region:     out["region"] = normalize_region(msg.region)
        if msg.status:     out["status"] = msg.status
        if msg.account_id: out["account_id"] = msg.account_id
        if out["token"]:
            return _fill_from_jwt(out)
    except Exception as e:
        log.debug(f"Proto parse failed: {e}")

    # 2. Decrypt then parse
    dec = decrypt_message(AES_KEY, AES_IV, raw_bytes)
    try:
        msg = output_pb2.Momin()
        msg.ParseFromString(dec)
        if msg.token:      out["token"] = msg.token
        if msg.region:     out["region"] = normalize_region(msg.region)
        if msg.status:     out["status"] = msg.status
        if msg.account_id: out["account_id"] = msg.account_id
        if out["token"]:
            return _fill_from_jwt(out)
    except Exception:
        pass

    # 3. Regex fallback
    text = dec.decode("utf-8", errors="ignore")
    m = re.search(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", text)
    if m:
        out["token"] = m.group(0)

    return _fill_from_jwt(out)

# ==================== BUILD GAME DATA ====================
def build_game_data(token_data):
    g = my_pb2.GameData()
    g.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")               # ✅ डायनामिक
    g.game_name = "free fire"
    g.game_version = 1
    g.version_code = CLIENT_VER
    g.os_info = "Android OS 13 / API-33 (TP1A.220624.014)"          # ✅ Android 13
    g.device_type = "Handheld"
    g.network_provider = "JIO"
    g.connection_type = "MOBILE"
    g.screen_width = 1080                                            # ✅ S23
    g.screen_height = 2340                                           # ✅ S23
    g.dpi = "420"                                                    # ✅ S23
    g.cpu_info = "ARM Cortex-A78 | 2400 | 8"                         # ✅ अनुमानित
    g.total_ram = 8192                                               # ✅ 8 GB
    g.gpu_name = "Adreno (TM) 740"                                   # ✅ Snapdragon 8 Gen 2
    g.gpu_version = "OpenGL ES 3.2"
    g.user_id = token_data.get("open_id", "")                        # open_id use करें
    g.ip_address = "182.75.115.22"                                   # ⚠️ अपने असली IP से बदलें
    g.language = "en"
    g.open_id = token_data["open_id"]
    g.access_token = token_data["access_token"]
    g.platform_type = 4
    g.device_form_factor = "Handheld"
    g.device_model = "Samsung Galaxy S23"                            # ✅ अपडेटेड
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
    g.field_92 = 8999
    g.marketplace = "3rd_party"
    g.encryption_key = "Jp2DT7F3Is55K/92LSJ4PWkJxZnMzSNn+HEBK2AFBDBdrLpWTA3bZjtbU3JbXigkIFFJ5ZJKi0fpnlJCPDD2A7h2aPQ="
    g.total_storage = 128000                                         # ✅ 128 GB
    g.field_97 = 1
    g.field_98 = 1
    g.field_99 = "4"
    g.field_100 = "4"
    return g

# ==================== RESPONSE BUILDER ====================
def build_response(success, uid, region=None, token=None, account_id=None,
                   nickname=None, status_code=200):
    region_code = normalize_region(region) if region else None
    login_url = region_to_url(region_code) if region_code else "N/A"

    return {
        "Success": bool(success),
        "Nickname": nickname or "",
        "Account_uid": str(account_id) if account_id else str(uid),
        "Region": region_code or "N/A",
        "Level": 0,
        "Prime_Level": 0,
        "Jwt_Token": token or "N/A",
        "Login_url": login_url,
        "Timestamp": int(time.time()),
        "Platform_type_used": PLATFORM,
        "Ob_version": OB_VERSION,
        "Client_Version": CLIENT_VER,
        "Develover": DEVELOPER,
        "Telegram": TELEGRAM,
        "Status_Code": status_code,
    }

# ==================== CORE: MAJOR LOGIN ====================
def _do_major_login(access_token, open_id):
    """Access token + open_id se MajorLogin karke JWT nikalo."""
    token_data = {
        "access_token": access_token,
        "open_id": open_id,
    }
    game_data = build_game_data(token_data)
    serialized = game_data.SerializeToString()
    encrypted  = encrypt_message(AES_KEY, AES_IV, serialized)

    headers = {
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept-Encoding": "deflate, gzip",
        "X-GA-SV": str(int(time.time())),                # ✅ डायनामिक
        "Authorization": "Bearer",
        "X-GA": "v1 1",
        "ReleaseVersion": OB_VERSION,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
    }

    log.info(f"MajorLogin for open_id={open_id}")
    response = requests.post(MAJOR_LOGIN_URL, data=encrypted,
                             headers=headers, verify=False, timeout=15)
    return response

# ==================== ROUTE: /token ====================
@app.route('/token', methods=['GET'])
def get_single_response():
    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify(build_response(
            success=False, uid=uid or "N/A", status_code=400
        )), 400

    token_data = get_token(password, uid)
    if not token_data:
        return jsonify(build_response(
            success=False, uid=uid, status_code=401
        )), 401

    try:
        response = _do_major_login(
            token_data["access_token"],
            token_data["open_id"]
        )

        if response.status_code != 200:
            return jsonify(build_response(
                success=False, uid=uid,
                status_code=response.status_code
            )), response.status_code

        parsed = parse_garena_response(response.content)

        return jsonify(build_response(
            success=bool(parsed["token"]),
            uid=uid,
            region=parsed["region"],
            token=parsed["token"],
            account_id=parsed["account_id"],
            nickname=parsed.get("nickname"),
            status_code=200 if parsed["token"] else 500
        )), 200 if parsed["token"] else 500

    except Exception as e:
        log.error(f"Internal error:\n{traceback.format_exc()}")
        return jsonify(build_response(
            success=False, uid=uid, status_code=500
        )), 500

# ==================== CORE: ACCESS TO JWT ====================
def _access_to_jwt_handler(access_token, open_id=None):
    if not access_token:
        return jsonify(build_response(
            success=False, uid="N/A", status_code=400
        )), 400

    # Try auto-extract if JWT
    if not open_id:
        open_id = _extract_open_id_from_token(access_token) or ""

    # Cache
    cache_key = f"{access_token}:{open_id}"
    if cache_key in _access_jwt_cache:
        return jsonify(_access_jwt_cache[cache_key]), 200

    try:
        response = _do_major_login(access_token, open_id)

        if response.status_code != 200:
            return jsonify(build_response(
                success=False, uid=open_id or "N/A",
                status_code=response.status_code
            )), response.status_code

        parsed = parse_garena_response(response.content)

        result = build_response(
            success=bool(parsed["token"]),
            uid=open_id or "N/A",
            region=parsed["region"],
            token=parsed["token"],
            account_id=parsed["account_id"],
            nickname=parsed.get("nickname"),
            status_code=200 if parsed["token"] else 500
        )

        if parsed["token"]:
            _access_jwt_cache[cache_key] = result

        return jsonify(result), 200 if parsed["token"] else 500

    except Exception as e:
        log.error(f"Internal error:\n{traceback.format_exc()}")
        return jsonify(build_response(
            success=False, uid=open_id or "N/A", status_code=500
        )), 500

# ==================== ROUTE: /access-to-jwt=XXX ====================
@app.route('/access-to-jwt=<path:access_token>', methods=['GET'])
def access_to_jwt_path(access_token):
    open_id = request.args.get('open_id')
    return _access_to_jwt_handler(access_token, open_id)

# ==================== ROUTE: /access-to-jwt?token=XXX ====================
@app.route('/access-to-jwt', methods=['GET'])
def access_to_jwt_query():
    access_token = (request.args.get('token')
                    or request.args.get('access_token')
                    or request.args.get('access'))
    open_id = request.args.get('open_id')
    return _access_to_jwt_handler(access_token, open_id)

# ==================== HEALTH ====================
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "timestamp": time.time()})

# ==================== MAIN ====================
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)