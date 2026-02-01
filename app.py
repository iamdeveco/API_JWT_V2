from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import httpx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
import eco_LoginReq
import eco_LoginRes
import eco_jwt
import eco_login
import json
import time
import warnings
from urllib3.exceptions import InsecureRequestWarning
from typing import Optional, Dict, Any
import logging
from contextlib import asynccontextmanager
from functools import lru_cache
from datetime import datetime, timedelta

# Disable SSL warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# Cache configuration
_CACHE: Dict[str, tuple[Dict[str, Any], datetime]] = {}
CACHE_TTL = timedelta(hours=7)

# FastAPI app with lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create async HTTP client
    app.state.http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(30.0),
        limits=httpx.Limits(max_keepalive_connections=100, max_connections=1000),
        http2=True,
        verify=False
    )
    yield
    # Shutdown: close HTTP client
    await app.state.http_client.aclose()

app = FastAPI(title="Game Auth API", lifespan=lifespan)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Cache utilities
def get_cache_key(uid: str, password: str) -> str:
    return f"{uid}:{password}"

def get_cached_response(uid: str, password: str) -> Optional[Dict[str, Any]]:
    cache_key = get_cache_key(uid, password)
    if cache_key in _CACHE:
        data, timestamp = _CACHE[cache_key]
        if datetime.now() - timestamp < CACHE_TTL:
            return data
        else:
            del _CACHE[cache_key]
    return None

def set_cached_response(uid: str, password: str, data: Dict[str, Any]):
    cache_key = get_cache_key(uid, password)
    _CACHE[cache_key] = (data, datetime.now())
    # Simple cache cleanup (remove old entries)
    if len(_CACHE) > 1000:
        oldest_keys = sorted(_CACHE.keys(), 
                           key=lambda k: _CACHE[k][1])[:100]
        for key in oldest_keys:
            del _CACHE[key]

# Async HTTP operations
async def get_token(password: str, uid: str, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
    try:
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
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
        
        response = await client.post(url, headers=headers, data=data)
        if response.status_code != 200:
            logger.warning(f"Token fetch failed: {response.status_code}")
            return None
        
        token_json = response.json()
        if "access_token" in token_json and "open_id" in token_json:
            return token_json
        return None
    except Exception as e:
        logger.error(f"Token fetch error: {e}")
        return None

# Run blocking operations in thread pool
async def encrypt_message_async(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return await asyncio.to_thread(encrypt_message, key, iv, plaintext)

def encrypt_message(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded)

def parse_response(content: str) -> Dict[str, str]:
    """Parse response content into dictionary, handling multiple formats"""
    response_dict = {}
    
    # Try parsing as key-value pairs with colons
    lines = content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip().strip('"')
            response_dict[key] = value
    
    # If no token found, try to extract from JSON-like structure
    if "token" not in response_dict and "token" in content:
        import re
        # Look for token:value pattern
        token_match = re.search(r'token["\']?\s*:\s*["\']?([^"\'\s,}]+)', content)
        if token_match:
            response_dict["token"] = token_match.group(1)
    
    # Also look for access_token
    if "token" not in response_dict and "access_token" in content:
        import re
        access_token_match = re.search(r'access_token["\']?\s*:\s*["\']?([^"\'\s,}]+)', content)
        if access_token_match:
            response_dict["token"] = access_token_match.group(1)
    
    return response_dict

async def prepare_major_login(token_data: Dict[str, Any]) -> bytes:
    """Prepare MajorLogin protobuf asynchronously"""
    def _prepare():
        major_login = eco_LoginReq.MajorLogin()
        major_login.event_time = "2025-06-04 19:48:07"
        major_login.game_name = "free fire"
        major_login.platform_id = 1
        major_login.client_version = "2.112.2"
        major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
        major_login.system_hardware = "Handheld"
        major_login.telecom_operator = "Verizon"
        major_login.network_type = "WIFI"
        major_login.screen_width = 1920
        major_login.screen_height = 1080
        major_login.screen_dpi = "280"
        major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
        major_login.memory = 3003
        major_login.gpu_renderer = "Adreno (TM) 640"
        major_login.gpu_version = "OpenGL ES 3.1 v1.46"
        major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
        major_login.client_ip = "223.191.51.89"
        major_login.language = "en"
        major_login.open_id = token_data['open_id']
        major_login.open_id_type = "4"
        major_login.device_type = "Handheld"
        
        # Set memory_available fields
        major_login.memory_available.version = 55
        major_login.memory_available.hidden_value = 81
        
        major_login.access_token = token_data['access_token']
        major_login.platform_sdk_id = 1
        major_login.network_operator_a = "Verizon"
        major_login.network_type_a = "WIFI"
        major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
        major_login.external_storage_total = 36235
        major_login.external_storage_available = 31335
        major_login.internal_storage_total = 2519
        major_login.internal_storage_available = 703
        major_login.game_disk_storage_available = 25010
        major_login.game_disk_storage_total = 26628
        major_login.external_sdcard_avail_storage = 32992
        major_login.external_sdcard_total_storage = 36235
        major_login.login_by = 3
        major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
        major_login.reg_avatar = 1
        major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
        major_login.channel_type = 3
        major_login.cpu_type = 2
        major_login.cpu_architecture = "64"
        major_login.client_version_code = "2019117863"
        major_login.graphics_api = "OpenGLES2"
        major_login.supported_astc_bitset = 16383
        major_login.login_open_id_type = 4
        major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWA0UO1Qs/A1snWlBaO1kFYg=="
        major_login.loading_time = 13564
        major_login.release_channel = "android"
        major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
        major_login.android_engine_init_flag = 110009
        major_login.if_push = 1
        major_login.is_vpn = 1
        major_login.origin_platform_type = "4"
        major_login.primary_platform_type = "4"
        
        return major_login.SerializeToString()
    
    return await asyncio.to_thread(_prepare)

async def parse_major_login_response(content: bytes) -> tuple[eco_LoginRes.MajorLoginRes, Dict[str, str]]:
    """Parse MajorLoginRes and JWT asynchronously"""
    def _parse():
        # Parse MajorLoginRes
        login_res = eco_LoginRes.MajorLoginRes()
        login_res.ParseFromString(content)
        
        # Parse jwt response
        jwt_msg = eco_jwt.Garena_420()
        jwt_msg.ParseFromString(content)
        jwt_dict = parse_response(str(jwt_msg))
        
        # Debug logging
        logger.info(f"JWT dict keys: {list(jwt_dict.keys())}")
        logger.info(f"Token in JWT dict: {jwt_dict.get('token', 'NOT FOUND')}")
        
        return login_res, jwt_dict
    
    return await asyncio.to_thread(_parse)

async def decrypt_login_data(content: bytes) -> eco_login.LoginReq:
    """Decrypt and parse LoginReq asynchronously"""
    def _decrypt():
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        decrypted_data = cipher.decrypt(content)
        
        # Remove padding
        padding_length = decrypted_data[-1]
        if padding_length <= AES.block_size:
            decrypted_data = decrypted_data[:-padding_length]
        
        # Parse the decrypted data
        login_info = eco_login.LoginReq()
        login_info.ParseFromString(decrypted_data)
        return login_info
    
    return await asyncio.to_thread(_decrypt)

@app.get("/token")
async def get_single_response(
    uid: str = Query(..., description="User ID"),
    password: str = Query(..., description="Password")
):
    """
    Get authentication token and user data.
    Cached for 7 hours.
    """
    start_time = time.time()
    
    # Check cache first
    cached = get_cached_response(uid, password)
    if cached:
        logger.info(f"Cache hit for UID: {uid}")
        cached['cached'] = True
        return JSONResponse(content=cached)
    
    # Get HTTP client from app state
    client = app.state.http_client
    
    # Get token
    token_data = await get_token(password, uid, client)
    if not token_data:
        error_response = {
            "uid": uid,
            "status": "invalid",
            "message": "Wrong UID or Password. Please check and try again."
        }
        raise HTTPException(status_code=400, detail=error_response)
    
    try:
        # Prepare MajorLogin asynchronously
        serialized = await prepare_major_login(token_data)
        
        # Encrypt asynchronously
        encrypted = await encrypt_message_async(AES_KEY, AES_IV, serialized)
        edata = binascii.hexlify(encrypted).decode()
        
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; Android 9)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB52"
        }
        
        # Make MajorLogin request
        response = await client.post(
            "https://loginbp.ggpolarbear.com/MajorLogin",
            content=bytes.fromhex(edata),
            headers=headers
        )
        
        # Debug: log the response
        logger.info(f"MajorLogin response status: {response.status_code}")
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail={"error": f"Failed MajorLogin: {response.status_code}"}
            )
        
        # Parse response asynchronously
        login_res, jwt_dict = await parse_major_login_response(response.content)
        
        # Get token - ensure it's not empty
        token = jwt_dict.get("token", "").strip()
        if not token:
            logger.error(f"Empty token received in response: {jwt_dict}")
            # Build response with available data
            response_data = {
                "accountId": login_res.account_id if hasattr(login_res, 'account_id') else "",
                "accountNickname": "", 
                "accountRegion": "", 
                "accountLevel": 0, 
                "accountLevelExp": 0, 
                "accountCreateAt": "", 
                "lockRegion": login_res.lock_region if hasattr(login_res, 'lock_region') else "",
                "notiRegion": login_res.noti_region if hasattr(login_res, 'noti_region') else "",
                "ipRegion": login_res.ip_region if hasattr(login_res, 'ip_region') else "",
                "agoraEnvironment": login_res.agora_environment if hasattr(login_res, 'agora_environment') else "",
                "tokenStatus": "invalid",
                "token": "", 
                "ttl": login_res.ttl if hasattr(login_res, 'ttl') else 0,
                "serverUrl": login_res.server_url if hasattr(login_res, 'server_url') else "",
                "expireAt": int(time.time()),
                "cached": False,
                "responseTime": round(time.time() - start_time, 3),
                "error": "Failed to obtain valid authentication token"
            }
            
            # Cache the response
            set_cached_response(uid, password, response_data)
            
            return JSONResponse(content=response_data)
        
        # Determine base URL
        base_url = None
        possible_url_fields = ['url', 'server_url', 'base_url', 'game_url', 'login_url']
        
        for field_name in possible_url_fields:
            if hasattr(login_res, field_name):
                url_value = getattr(login_res, field_name)
                if url_value and url_value.strip():
                    base_url = url_value
                    break
        
        if not base_url:
            base_url = "https://loginbp.ggpolarbear.com"
        
        # Prepare LoginReq for GetLoginData
        login_req = eco_login.LoginReq()
        login_req.account_id = login_res.account_id
        serialized_login = await asyncio.to_thread(login_req.SerializeToString)
        encrypted_login = await encrypt_message_async(AES_KEY, AES_IV, serialized_login)
        login_hex = binascii.hexlify(encrypted_login).decode()
        
        # Only set Authorization header if token is valid
        get_headers = headers.copy()
        get_headers["Authorization"] = f"Bearer {token}"
        
        # Make GetLoginData request
        get_login_url = f"{base_url}/GetLoginData"
        get_resp = await client.post(
            get_login_url,
            content=bytes.fromhex(login_hex),
            headers=get_headers
        )
        
        nickname = region = level = exp = create_at = ""
        
        if get_resp.status_code == 200:
            try:
                login_info = await decrypt_login_data(get_resp.content)
                nickname = login_info.nickname
                region = login_info.region
                level = login_info.level
                exp = login_info.exp
                create_at = login_info.create_at
                logger.info(f"Successfully parsed user data: {nickname}, {region}, Level {level}")
            except Exception as e:
                logger.warning(f"Decryption failed, trying direct parse: {e}")
                try:
                    login_info = eco_login.LoginReq()
                    login_info.ParseFromString(get_resp.content)
                    nickname = login_info.nickname
                    region = login_info.region
                    level = login_info.level
                    exp = login_info.exp
                    create_at = login_info.create_at
                except Exception as e2:
                    logger.error(f"Direct parsing also failed: {e2}")
        else:
            logger.warning(f"GetLoginData failed with status: {get_resp.status_code}")
        
        # Build response
        response_data = {
            "accountId": login_res.account_id if hasattr(login_res, 'account_id') else "",
            "accountNickname": nickname, 
            "accountRegion": region, 
            "accountLevel": level, 
            "accountLevelExp": exp, 
            "accountCreateAt": create_at, 
            "lockRegion": login_res.lock_region if hasattr(login_res, 'lock_region') else "",
            "notiRegion": login_res.noti_region if hasattr(login_res, 'noti_region') else "",
            "ipRegion": login_res.ip_region if hasattr(login_res, 'ip_region') else "",
            "agoraEnvironment": login_res.agora_environment if hasattr(login_res, 'agora_environment') else "",
            "tokenStatus": jwt_dict.get("status", "valid"),
            "token": token, 
            "ttl": login_res.ttl if hasattr(login_res, 'ttl') else 0,
            "serverUrl": login_res.server_url if hasattr(login_res, 'server_url') else "",
            "expireAt": int(time.time()) + (login_res.ttl if hasattr(login_res, 'ttl') else 0),
            "cached": False,
            "responseTime": round(time.time() - start_time, 3)
        }
        
        # Cache the response
        set_cached_response(uid, password, response_data)
        
        return JSONResponse(content=response_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail={"error": str(e)})

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": time.time()}

@app.get("/cache/stats")
async def cache_stats():
    """Get cache statistics"""
    return {
        "size": len(_CACHE),
        "max_size": 1000,
        "ttl_hours": 7
    }

# Premium UI Route
@app.get("/", response_class=HTMLResponse)
async def get_premium_ui():
    """Serve the premium UI dashboard"""
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Game Auth API | Premium Dashboard</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /* TSun Info - Professional Design System */
        /* Hand-crafted with logic and precision. */

        :root {
            /* Color Palette - Dark & Premium */
            --bg-core: #050505;
            --bg-surface: #0f0f0f;
            --bg-surface-hover: #1a1a1a;
            --bg-glass: rgba(20, 20, 20, 0.7);

            --primary-hue: 16;
            /* Orange-Red */
            --primary: hsl(var(--primary-hue), 100%, 50%);
            --primary-dim: hsl(var(--primary-hue), 100%, 30%);
            --primary-glow: hsla(var(--primary-hue), 100%, 50%, 0.3);

            --accent-cyan: #00f2ff;
            --accent-purple: #bd00ff;

            --text-main: #ffffff;
            --text-muted: #a0a0a0;
            --text-dim: #505050;

            --border-light: rgba(255, 255, 255, 0.1);
            --border-active: rgba(255, 69, 0, 0.5);

            --success: #00ff9d;
            --error: #ff2a6d;

            /* Spacing & Layout */
            --radius-sm: 4px;
            --radius-md: 8px;
            --radius-lg: 16px;
            --radius-full: 9999px;

            --space-xs: 0.5rem;
            --space-sm: 1rem;
            --space-md: 2rem;
            --space-lg: 4rem;

            /* Typography */
            --font-ui: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            --font-display: 'Outfit', sans-serif;
            --font-mono: 'JetBrains Mono', monospace;

            /* Animation */
            --ease-out: cubic-bezier(0.215, 0.61, 0.355, 1);
            --ease-in-out: cubic-bezier(0.645, 0.045, 0.355, 1);
        }

        /* Reset & Base */
        *,
        *::before,
        *::after {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            background-color: var(--bg-core);
            color: var(--text-main);
            font-family: var(--font-ui);
            line-height: 1.6;
            overflow-x: hidden;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        /* Typography */
        h1,
        h2,
        h3,
        h4,
        h5,
        h6 {
            font-family: var(--font-display);
            font-weight: 700;
            line-height: 1.2;
            letter-spacing: -0.02em;
        }

        a {
            color: var(--primary);
            text-decoration: none;
            transition: color 0.2s ease;
        }

        a:hover {
            color: #fff;
        }

        /* Background Effects */
        .bg-mesh {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            z-index: -1;
            background:
                radial-gradient(circle at 15% 50%, rgba(255, 69, 0, 0.08), transparent 25%),
                radial-gradient(circle at 85% 30%, rgba(189, 0, 255, 0.05), transparent 25%);
            pointer-events: none;
        }

        .grid-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image:
                linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            z-index: -1;
            mask-image: radial-gradient(circle at center, black 40%, transparent 100%);
            -webkit-mask-image: radial-gradient(circle at center, black 40%, transparent 100%);
            pointer-events: none;
        }

        /* Layout Containers */
        .app-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: var(--space-md);
            width: 100%;
            flex: 1;
            display: flex;
            flex-direction: column;
        }

        /* Header */
        .main-header {
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            gap: var(--space-md);
            padding: var(--space-md) 0;
            margin-bottom: var(--space-lg);
            border-bottom: 1px solid var(--border-light);
        }

        .brand {
            display: flex;
            align-items: center;
            gap: var(--space-sm);
        }

        .brand-logo {
            font-size: 1.5rem;
            animation: pulse-fire 3s infinite;
        }

        .brand-text {
            font-family: var(--font-display);
            font-size: 1.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #fff 0%, var(--text-muted) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .brand-badge {
            font-family: var(--font-mono);
            font-size: 0.75rem;
            background: var(--bg-surface-hover);
            padding: 2px 8px;
            border-radius: var(--radius-sm);
            color: var(--primary);
            border: 1px solid var(--primary-dim);
        }

        /* Navigation Tabs */
        .nav-tabs {
            display: flex;
            gap: var(--space-sm);
            background: var(--bg-surface);
            padding: 6px;
            border-radius: var(--radius-lg);
            width: fit-content;
            margin: 0 auto;
            border: 1px solid var(--border-light);
        }

        .nav-btn {
            background: transparent;
            border: none;
            color: var(--text-muted);
            padding: 10px 24px;
            border-radius: var(--radius-md);
            cursor: pointer;
            font-family: var(--font-ui);
            font-weight: 600;
            font-size: 0.95rem;
            transition: all 0.3s var(--ease-out);
            position: relative;
            overflow: hidden;
        }

        .nav-btn:hover {
            color: var(--text-main);
            background: rgba(255, 255, 255, 0.05);
        }

        .nav-btn.active {
            color: var(--bg-core);
            background: var(--text-main);
            box-shadow: 0 0 20px rgba(255, 255, 255, 0.2);
        }

        /* Content Sections */
        .tab-content {
            display: none;
            animation: fade-in-up 0.5s var(--ease-out);
        }

        .tab-content.active {
            display: block;
        }

        /* Search Interface */
        .search-interface {
            max-width: 600px;
            margin: 0 auto var(--space-lg);
            text-align: center;
        }

        .search-title {
            font-size: 2rem;
            margin-bottom: var(--space-sm);
            background: linear-gradient(to right, #fff, #a0a0a0);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .search-subtitle {
            color: var(--text-muted);
            margin-bottom: var(--space-md);
            font-size: 1.1rem;
        }

        .input-group {
            position: relative;
            display: flex;
            gap: var(--space-xs);
        }

        .search-input {
            flex: 1;
            background: var(--bg-surface);
            border: 1px solid var(--border-light);
            padding: 16px 20px;
            border-radius: var(--radius-md);
            color: var(--text-main);
            font-family: var(--font-mono);
            font-size: 1rem;
            transition: all 0.3s ease;
        }

        .search-input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 4px var(--primary-glow);
            background: var(--bg-surface-hover);
        }

        .action-btn {
            background: var(--primary);
            color: white;
            border: none;
            padding: 0 32px;
            border-radius: var(--radius-md);
            font-weight: 700;
            font-family: var(--font-display);
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .action-btn:hover {
            background: #ff5e00;
            transform: translateY(-2px);
            box-shadow: 0 10px 20px -5px var(--primary-glow);
        }

        /* Results Grid */
        .results-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: var(--space-md);
            margin-top: var(--space-md);
        }

        .data-card {
            background: var(--bg-glass);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-lg);
            padding: var(--space-md);
            transition: transform 0.3s var(--ease-out), border-color 0.3s ease;
        }

        .data-card:hover {
            transform: translateY(-4px);
            border-color: var(--border-active);
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: var(--space-md);
            padding-bottom: var(--space-sm);
            border-bottom: 1px solid var(--border-light);
        }

        .card-title {
            font-size: 1.1rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .card-icon {
            color: var(--primary);
        }

        /* Info Rows */
        .info-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
        }

        .info-row:last-child {
            border-bottom: none;
        }

        .info-label {
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        .info-value {
            font-family: var(--font-mono);
            font-weight: 600;
            color: var(--text-main);
            text-align: right;
        }

        .info-value.highlight {
            color: var(--primary);
        }

        /* Badges */
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 4px 10px;
            border-radius: var(--radius-full);
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .badge-region {
            background: rgba(0, 242, 255, 0.1);
            color: var(--accent-cyan);
            border: 1px solid rgba(0, 242, 255, 0.2);
        }

        .badge-rank {
            background: rgba(255, 69, 0, 0.1);
            color: var(--primary);
            border: 1px solid rgba(255, 69, 0, 0.2);
        }

        /* Loading State */
        .loading-container {
            display: none;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: var(--space-lg);
        }

        .loader {
            width: 48px;
            height: 48px;
            border: 3px solid var(--text-dim);
            border-radius: 50%;
            display: inline-block;
            position: relative;
            box-sizing: border-box;
            animation: rotation 1s linear infinite;
        }

        .loader::after {
            content: '';
            box-sizing: border-box;
            position: absolute;
            left: 50%;
            top: 50%;
            transform: translate(-50%, -50%);
            width: 40px;
            height: 40px;
            border-radius: 50%;
            border: 3px solid transparent;
            border-bottom-color: var(--primary);
        }

        @keyframes rotation {
            0% {
                transform: rotate(0deg);
            }

            100% {
                transform: rotate(360deg);
            }
        }

        /* Animations */
        @keyframes fade-in-up {
            from {
                opacity: 0;
                transform: translateY(20px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes pulse-fire {
            0% {
                text-shadow: 0 0 10px rgba(255, 69, 0, 0.5);
            }

            50% {
                text-shadow: 0 0 20px rgba(255, 69, 0, 0.8), 0 0 30px rgba(255, 140, 0, 0.6);
            }

            100% {
                text-shadow: 0 0 10px rgba(255, 69, 0, 0.5);
            }
        }

        /* Footer */
        .main-footer {
            padding: var(--space-md);
            text-align: center;
            color: var(--text-dim);
            font-size: 0.9rem;
            border-top: 1px solid var(--border-light);
            margin-top: auto;
        }

        .footer-link {
            color: var(--text-muted);
            margin: 0 10px;
            position: relative;
        }

        .footer-link::after {
            content: '';
            position: absolute;
            bottom: -2px;
            left: 0;
            width: 0;
            height: 1px;
            background: var(--primary);
            transition: width 0.3s ease;
        }

        .footer-link:hover::after {
            width: 100%;
        }

        /* API Docs Specifics */
        .docs-container {
            max-width: 900px;
            margin: 0 auto;
        }

        .endpoint-block {
            background: var(--bg-surface);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-md);
            margin-bottom: var(--space-md);
            overflow: hidden;
        }

        .endpoint-header {
            padding: 15px 20px;
            background: rgba(255, 255, 255, 0.02);
            display: flex;
            align-items: center;
            gap: 15px;
            border-bottom: 1px solid var(--border-light);
        }

        .method {
            font-family: var(--font-mono);
            font-weight: 800;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
        }

        .method.get {
            background: rgba(0, 255, 157, 0.1);
            color: var(--success);
        }

        .method.post {
            background: rgba(255, 184, 0, 0.1);
            color: #ffb800;
        }

        .path {
            font-family: var(--font-mono);
            color: var(--text-main);
        }

        .endpoint-body {
            padding: 20px;
        }

        .code-snippet {
            background: #000;
            padding: 15px;
            border-radius: var(--radius-md);
            font-family: var(--font-mono);
            font-size: 0.9rem;
            color: #a0a0a0;
            overflow-x: auto;
            border: 1px solid var(--border-light);
        }

        /* JSON Viewer Styles */
        .json-viewer {
            max-height: 600px;
            overflow: auto;
            background: #000;
            border-radius: var(--radius-md);
            border: 1px solid var(--border-light);
        }

        .json-code {
            margin: 0;
            padding: 20px;
            font-family: var(--font-mono);
            font-size: 0.9rem;
            line-height: 1.6;
            color: #a0a0a0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }

        /* JSON Syntax Highlighting */
        .json-key {
            color: #00f2ff;
            font-weight: 600;
        }

        .json-string {
            color: #00ff9d;
        }

        .json-number {
            color: #bd00ff;
        }

        .json-boolean {
            color: var(--primary);
            font-weight: 700;
        }

        .json-null {
            color: #ff2a6d;
            font-style: italic;
        }

        /* Copy Button */
        .copy-btn {
            display: flex;
            align-items: center;
            gap: 6px;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid var(--border-light);
            color: var(--text-main);
            padding: 8px 16px;
            border-radius: var(--radius-sm);
            cursor: pointer;
            font-family: var(--font-ui);
            font-size: 0.85rem;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .copy-btn:hover {
            background: rgba(255, 255, 255, 0.15);
            border-color: var(--primary);
            transform: translateY(-1px);
        }

        .copy-btn svg {
            width: 16px;
            height: 16px;
        }

        /* Scrollbar Styling */
        .json-viewer::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        .json-viewer::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 4px;
        }

        .json-viewer::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.2);
            border-radius: 4px;
        }

        .json-viewer::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 255, 255, 0.3);
        }

        /* Responsive */
        @media (max-width: 768px) {
            .nav-tabs {
                width: 100%;
                overflow-x: auto;
                justify-content: flex-start;
                padding: 4px;
            }

            .nav-btn {
                padding: 8px 16px;
                white-space: nowrap;
            }

            .input-group {
                flex-direction: column;
            }

            .action-btn {
                width: 100%;
                padding: 16px;
            }

            .results-grid {
                grid-template-columns: 1fr;
            }
        }

        /* Toast Notifications */
        .toast {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: var(--bg-surface);
            border-left: 4px solid var(--primary);
            padding: 16px 24px;
            border-radius: var(--radius-md);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            display: none;
            align-items: center;
            gap: 12px;
            z-index: 1000;
            animation: slide-in 0.3s var(--ease-out);
        }

        @keyframes slide-in {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }

        .toast.success {
            border-left-color: var(--success);
        }

        .toast.error {
            border-left-color: var(--error);
        }

        .toast-icon {
            font-size: 1.2rem;
        }

        .toast.success .toast-icon {
            color: var(--success);
        }

        .toast.error .toast-icon {
            color: var(--error);
        }

        /* Token Display Styles */
        .token-display {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-sm);
            padding: 8px 12px;
            margin: 8px 0;
            font-family: var(--font-mono);
            font-size: 0.8rem;
        }

        .token-text {
            color: var(--text-muted);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            flex: 1;
            margin-right: 10px;
        }

        .token-copy-btn {
            background: var(--primary);
            color: white;
            border: none;
            padding: 4px 12px;
            border-radius: var(--radius-sm);
            cursor: pointer;
            font-size: 0.75rem;
            font-weight: 600;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 4px;
            white-space: nowrap;
        }

        .token-copy-btn:hover {
            background: #ff5e00;
            transform: translateY(-1px);
        }

        .token-copy-btn:active {
            transform: translateY(0);
        }

        .token-copy-btn.copied {
            background: var(--success);
        }

        /* Full Token Modal */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(4px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 2000;
            padding: 20px;
        }

        .modal-content {
            background: var(--bg-surface);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-lg);
            padding: var(--space-md);
            max-width: 800px;
            width: 100%;
            max-height: 80vh;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: var(--space-md);
            padding-bottom: var(--space-sm);
            border-bottom: 1px solid var(--border-light);
        }

        .modal-title {
            font-size: 1.2rem;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .modal-close {
            background: transparent;
            border: none;
            color: var(--text-muted);
            font-size: 1.5rem;
            cursor: pointer;
            padding: 4px;
            line-height: 1;
        }

        .modal-close:hover {
            color: var(--text-main);
        }

        .modal-body {
            flex: 1;
            overflow: auto;
            margin-bottom: var(--space-md);
        }

        .full-token {
            background: #000;
            color: var(--text-muted);
            font-family: var(--font-mono);
            font-size: 0.85rem;
            padding: 16px;
            border-radius: var(--radius-sm);
            border: 1px solid var(--border-light);
            white-space: pre-wrap;
            word-break: break-all;
            line-height: 1.4;
        }

        .modal-actions {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
        }

        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: var(--text-main);
            border: 1px solid var(--border-light);
            padding: 8px 20px;
            border-radius: var(--radius-sm);
            cursor: pointer;
            font-family: var(--font-ui);
            font-size: 0.9rem;
            transition: all 0.2s ease;
        }

        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.15);
        }

        .btn-primary {
            background: var(--primary);
            color: white;
            border: none;
            padding: 8px 20px;
            border-radius: var(--radius-sm);
            cursor: pointer;
            font-family: var(--font-ui);
            font-size: 0.9rem;
            transition: all 0.2s ease;
        }

        .btn-primary:hover {
            background: #ff5e00;
        }

        .view-token-btn {
            background: transparent;
            border: 1px solid var(--border-light);
            color: var(--text-muted);
            padding: 2px 8px;
            border-radius: var(--radius-sm);
            font-size: 0.7rem;
            cursor: pointer;
            margin-left: 5px;
        }

        .view-token-btn:hover {
            color: var(--primary);
            border-color: var(--primary);
        }
    </style>
</head>
<body>
    <!-- Background Effects -->
    <div class="bg-mesh"></div>
    <div class="grid-overlay"></div>

    <!-- Token Modal -->
    <div id="token-modal" class="modal-overlay">
        <div class="modal-content">
            <div class="modal-header">
                <div class="modal-title">
                    <i class="fas fa-key"></i>
                    Full Authentication Token
                </div>
                <button class="modal-close" id="modal-close">&times;</button>
            </div>
            <div class="modal-body">
                <div id="full-token" class="full-token"></div>
            </div>
            <div class="modal-actions">
                <button class="btn-secondary" id="modal-copy">
                    <i class="fas fa-copy"></i> Copy Token
                </button>
                <button class="btn-primary" id="modal-close-btn">Close</button>
            </div>
        </div>
    </div>

    <!-- Main Container -->
    <div class="app-container">
        <!-- Header -->
        <header class="main-header">
            <div class="brand">
                <div class="brand-logo">
                    <i class="fas fa-fire" style="color: var(--primary);"></i>
                </div>
                <div class="brand-text">Game Auth API</div>
                <div class="brand-badge">v2.1.0</div>
            </div>
            
            <!-- Navigation Tabs -->
            <nav class="nav-tabs">
                <button class="nav-btn active" data-tab="home">
                    <i class="fas fa-home"></i> Home
                </button>
                <button class="nav-btn" data-tab="docs">
                    <i class="fas fa-book"></i> API Docs
                </button>
                <button class="nav-btn" data-tab="cache">
                    <i class="fas fa-database"></i> Cache Stats
                </button>
            </nav>
        </header>

        <!-- Toast Notification -->
        <div id="toast" class="toast">
            <span class="toast-icon"></span>
            <span class="toast-message">Notification message</span>
        </div>

        <!-- Home Tab -->
        <section id="home" class="tab-content active">
            <div class="search-interface">
                <h1 class="search-title">Authentication Dashboard</h1>
                <p class="search-subtitle">Enter your credentials to retrieve account data with 7-hour caching</p>
                
                <div class="input-group">
                    <input type="text" id="uid" class="search-input" placeholder="Enter User ID" autocomplete="off">
                    <input type="password" id="password" class="search-input" placeholder="Enter Password" autocomplete="off">
                    <button id="fetch-btn" class="action-btn">
                        <i class="fas fa-key"></i> Fetch Data
                    </button>
                </div>
            </div>

            <!-- Loading State -->
            <div id="loading" class="loading-container">
                <div class="loader"></div>
                <p style="margin-top: 20px; color: var(--text-muted);">Fetching account data...</p>
            </div>

            <!-- Results Grid -->
            <div id="results" class="results-grid">
                <!-- Cards will be populated here -->
            </div>
        </section>

        <!-- API Docs Tab -->
        <section id="docs" class="tab-content">
            <div class="docs-container">
                <h1 style="margin-bottom: var(--space-md);">API Documentation</h1>
                
                <!-- GET /token -->
                <div class="endpoint-block">
                    <div class="endpoint-header">
                        <span class="method get">GET</span>
                        <span class="path">/token</span>
                    </div>
                    <div class="endpoint-body">
                        <p style="margin-bottom: 15px; color: var(--text-muted);">Get authentication token and user data. Cached for 7 hours.</p>
                        
                        <h4 style="margin-bottom: 10px; color: var(--text-main);">Parameters:</h4>
                        <div class="code-snippet">
                            <code>
                                uid (string, required) - User ID<br>
                                password (string, required) - Password
                            </code>
                        </div>
                        
                        <h4 style="margin: 15px 0 10px; color: var(--text-main);">Example Request:</h4>
                        <div class="code-snippet">
                            <code>
                                GET /token?uid=123456789&password=secret123
                            </code>
                        </div>
                        
                        <h4 style="margin: 15px 0 10px; color: var(--text-main);">Response Format:</h4>
                        <div class="json-viewer">
                            <pre id="json-example" class="json-code"></pre>
                        </div>
                    </div>
                </div>

                <!-- GET /health -->
                <div class="endpoint-block">
                    <div class="endpoint-header">
                        <span class="method get">GET</span>
                        <span class="path">/health</span>
                    </div>
                    <div class="endpoint-body">
                        <p style="color: var(--text-muted);">Health check endpoint to verify API status.</p>
                    </div>
                </div>

                <!-- GET /cache/stats -->
                <div class="endpoint-block">
                    <div class="endpoint-header">
                        <span class="method get">GET</span>
                        <span class="path">/cache/stats</span>
                    </div>
                    <div class="endpoint-body">
                        <p style="color: var(text-muted);">Get cache statistics including size and TTL.</p>
                    </div>
                </div>
            </div>
        </section>

        <!-- Cache Stats Tab -->
        <section id="cache" class="tab-content">
            <div class="docs-container">
                <h1 style="margin-bottom: var(--space-md);">Cache Statistics</h1>
                
                <div id="cache-stats" class="results-grid">
                    <!-- Cache stats will be populated here -->
                </div>
                
                <button id="refresh-cache" class="action-btn" style="margin-top: var(--space-md);">
                    <i class="fas fa-sync-alt"></i> Refresh Cache Stats
                </button>
            </div>
        </section>
    </div>

    <!-- Footer -->
    <footer class="main-footer">
        <p>Game Auth API v2.1.0 | Built with FastAPI & Premium UI</p>
        <p style="margin-top: 10px;">
            <a href="#" class="footer-link">Privacy Policy</a> |
            <a href="#" class="footer-link">Terms of Service</a> |
            <a href="#" class="footer-link">API Status</a>
        </p>
    </footer>

    <script>
        // API Base URL - automatically uses current host
        const API_BASE = window.location.origin;

        // DOM Elements
        const tabButtons = document.querySelectorAll('.nav-btn');
        const tabContents = document.querySelectorAll('.tab-content');
        const fetchBtn = document.getElementById('fetch-btn');
        const uidInput = document.getElementById('uid');
        const passwordInput = document.getElementById('password');
        const loadingEl = document.getElementById('loading');
        const resultsEl = document.getElementById('results');
        const jsonExampleEl = document.getElementById('json-example');
        const cacheStatsEl = document.getElementById('cache-stats');
        const refreshCacheBtn = document.getElementById('refresh-cache');
        const toastEl = document.getElementById('toast');
        const tokenModal = document.getElementById('token-modal');
        const fullTokenEl = document.getElementById('full-token');
        const modalCloseBtns = document.querySelectorAll('#modal-close, #modal-close-btn');
        const modalCopyBtn = document.getElementById('modal-copy');

        // Example JSON for docs
        const exampleJson = {
            "accountId": "1234567890123456",
            "accountNickname": "PremiumPlayer",
            "accountRegion": "us",
            "accountLevel": 75,
            "accountLevelExp": 12500,
            "accountCreateAt": "2020-05-15",
            "lockRegion": "",
            "notiRegion": "us",
            "ipRegion": "US",
            "agoraEnvironment": "production",
            "tokenStatus": "valid",
            "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "ttl": 25200,
            "serverUrl": "https://loginbp.ggpolarbear.com",
            "expireAt": 1736359200,
            "cached": false,
            "responseTime": 1.234
        };

        // Format JSON with syntax highlighting
        function syntaxHighlight(json) {
            if (typeof json != 'string') {
                json = JSON.stringify(json, null, 2);
            }
            json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            return json.replace(
                /("(\\\\u[a-zA-Z0-9]{4}|\\\\[^u]|[^\\\\"])*"(\\s*:)?|\\b(true|false|null)\\b|-?\\d+(?:\\.\\d*)?(?:[eE][+\\-]?\\d+)?)/g,
                function(match) {
                    let cls = 'json-number';
                    if (/^"/.test(match)) {
                        if (/:$/.test(match)) {
                            cls = 'json-key';
                        } else {
                            cls = 'json-string';
                        }
                    } else if (/true|false/.test(match)) {
                        cls = 'json-boolean';
                    } else if (/null/.test(match)) {
                        cls = 'json-null';
                    }
                    return '<span class="' + cls + '">' + match + '</span>';
                }
            );
        }

        // Initialize JSON example in docs
        jsonExampleEl.innerHTML = syntaxHighlight(exampleJson);

        // Tab Switching
        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const tabId = button.getAttribute('data-tab');
                
                // Update active tab button
                tabButtons.forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');
                
                // Show selected tab content
                tabContents.forEach(content => content.classList.remove('active'));
                document.getElementById(tabId).classList.add('active');
                
                // Load cache stats if cache tab is selected
                if (tabId === 'cache') {
                    loadCacheStats();
                }
            });
        });

        // Show toast notification
        function showToast(message, type = 'info') {
            const icon = toastEl.querySelector('.toast-icon');
            const msg = toastEl.querySelector('.toast-message');
            
            toastEl.className = `toast ${type}`;
            icon.className = 'toast-icon';
            
            if (type === 'success') {
                icon.innerHTML = '<i class="fas fa-check-circle"></i>';
            } else if (type === 'error') {
                icon.innerHTML = '<i class="fas fa-exclamation-circle"></i>';
            } else {
                icon.innerHTML = '<i class="fas fa-info-circle"></i>';
            }
            
            msg.textContent = message;
            toastEl.style.display = 'flex';
            
            setTimeout(() => {
                toastEl.style.display = 'none';
            }, 3000);
        }

        // Format timestamp to readable date
        function formatTimestamp(timestamp) {
            if (!timestamp) return 'N/A';
            const date = new Date(timestamp * 1000);
            return date.toLocaleString();
        }

        // Copy text to clipboard
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                showToast('Copied to clipboard!', 'success');
            }).catch(err => {
                console.error('Failed to copy: ', err);
                showToast('Failed to copy to clipboard', 'error');
            });
        }

        // Show token modal
        function showTokenModal(token) {
            fullTokenEl.textContent = token;
            tokenModal.style.display = 'flex';
        }

        // Close token modal
        function closeTokenModal() {
            tokenModal.style.display = 'none';
        }

        // Create result card
        function createResultCard(data) {
            const card = document.createElement('div');
            card.className = 'data-card';
            
            // Truncate token for display
            const truncatedToken = data.token ? 
                (data.token.length > 30 ? data.token.substring(0, 30) + '...' : data.token) : 
                'No token available';
            
            card.innerHTML = `
                <div class="card-header">
                    <div class="card-title">
                        <i class="fas fa-user-circle card-icon"></i>
                        Account Information
                    </div>
                    ${data.cached ? 
                        '<span style="color: var(--success); font-size: 0.8rem;"><i class="fas fa-bolt"></i> CACHED</span>' : 
                        '<span style="color: var(--text-muted); font-size: 0.8rem;"><i class="fas fa-cloud-download-alt"></i> LIVE</span>'
                    }
                </div>
                
                <div class="info-row">
                    <span class="info-label">Account ID</span>
                    <span class="info-value" style="font-family: var(--font-mono); font-size: 0.85rem;">${data.accountId || 'N/A'}</span>
                </div>
                
                <div class="info-row">
                    <span class="info-label">Nickname</span>
                    <span class="info-value highlight">${data.accountNickname || 'N/A'}</span>
                </div>
                
                <div class="info-row">
                    <span class="info-label">Region</span>
                    <span class="badge badge-region">${data.accountRegion || 'N/A'}</span>
                </div>
                
                <div class="info-row">
                    <span class="info-label">Level</span>
                    <span class="badge badge-rank">${data.accountLevel || '0'}</span>
                </div>
                
                <div class="info-row">
                    <span class="info-label">Experience</span>
                    <span class="info-value">${data.accountLevelExp || '0'} XP</span>
                </div>
                
                <div class="info-row">
                    <span class="info-label">Created</span>
                    <span class="info-value">${data.accountCreateAt || 'N/A'}</span>
                </div>
                
                <div class="info-row">
                    <span class="info-label">Token Status</span>
                    <span style="color: ${data.tokenStatus === 'valid' ? 'var(--success)' : 'var(--error)'}; 
                          font-weight: 600; text-transform: uppercase;">
                        ${data.tokenStatus || 'invalid'}
                    </span>
                </div>
                
                <div style="margin: 15px 0;">
                    <div style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 8px;">Authentication Token</div>
                    <div class="token-display">
                        <span class="token-text" title="${data.token || ''}">${truncatedToken}</span>
                        <div style="display: flex; gap: 5px;">
                            ${data.token ? `
                                <button class="token-copy-btn" data-token="${data.token}">
                                    <i class="fas fa-copy"></i> Copy
                                </button>
                                <button class="view-token-btn" data-token="${data.token}">
                                    <i class="fas fa-eye"></i>
                                </button>
                            ` : '<span style="color: var(--text-dim); font-size: 0.8rem;">No token</span>'}
                        </div>
                    </div>
                </div>
                
                <div class="info-row">
                    <span class="info-label">Token Expires</span>
                    <span class="info-value">${formatTimestamp(data.expireAt)}</span>
                </div>
                
                <div class="info-row">
                    <span class="info-label">Response Time</span>
                    <span class="info-value">${data.responseTime || '0'}s</span>
                </div>
            `;
            
            // Add event listeners for copy buttons in this card
            const copyBtn = card.querySelector('.token-copy-btn');
            const viewBtn = card.querySelector('.view-token-btn');
            
            if (copyBtn) {
                copyBtn.addEventListener('click', function() {
                    const token = this.getAttribute('data-token');
                    copyToClipboard(token);
                    
                    // Visual feedback
                    this.innerHTML = '<i class="fas fa-check"></i> Copied!';
                    this.classList.add('copied');
                    
                    setTimeout(() => {
                        this.innerHTML = '<i class="fas fa-copy"></i> Copy';
                        this.classList.remove('copied');
                    }, 2000);
                });
            }
            
            if (viewBtn) {
                viewBtn.addEventListener('click', function() {
                    const token = this.getAttribute('data-token');
                    showTokenModal(token);
                });
            }
            
            return card;
        }

        // Load cache statistics
        async function loadCacheStats() {
            try {
                const response = await fetch(`${API_BASE}/cache/stats`);
                const data = await response.json();
                
                cacheStatsEl.innerHTML = '';
                
                const statsCard = document.createElement('div');
                statsCard.className = 'data-card';
                statsCard.innerHTML = `
                    <div class="card-header">
                        <div class="card-title">
                            <i class="fas fa-database card-icon"></i>
                            Cache Statistics
                        </div>
                    </div>
                    
                    <div class="info-row">
                        <span class="info-label">Current Size</span>
                        <span class="info-value highlight">${data.size || 0} entries</span>
                    </div>
                    
                    <div class="info-row">
                        <span class="info-label">Max Capacity</span>
                        <span class="info-value">${data.max_size || 1000} entries</span>
                    </div>
                    
                    <div class="info-row">
                        <span class="info-label">Cache TTL</span>
                        <span class="info-value">${data.ttl_hours || 7} hours</span>
                    </div>
                    
                    <div class="info-row">
                        <span class="info-label">Utilization</span>
                        <span class="info-value">
                            ${Math.round((data.size / data.max_size) * 100) || 0}%
                        </span>
                    </div>
                `;
                
                cacheStatsEl.appendChild(statsCard);
                
                // Add health check card
                const healthCard = document.createElement('div');
                healthCard.className = 'data-card';
                healthCard.innerHTML = `
                    <div class="card-header">
                        <div class="card-title">
                            <i class="fas fa-heartbeat card-icon"></i>
                            System Health
                        </div>
                    </div>
                    
                    <div class="info-row">
                        <span class="info-label">API Status</span>
                        <span style="color: var(--success); font-weight: 600;">
                            <i class="fas fa-check-circle"></i> Operational
                        </span>
                    </div>
                    
                    <div class="info-row">
                        <span class="info-label">Last Updated</span>
                        <span class="info-value">${new Date().toLocaleTimeString()}</span>
                    </div>
                    
                    <div class="info-row">
                        <span class="info-label">Cache Performance</span>
                        <span class="info-value">High</span>
                    </div>
                `;
                
                cacheStatsEl.appendChild(healthCard);
                
            } catch (error) {
                console.error('Error loading cache stats:', error);
                showToast('Failed to load cache statistics', 'error');
            }
        }

        // Fetch account data
        async function fetchAccountData() {
            const uid = uidInput.value.trim();
            const password = passwordInput.value.trim();
            
            if (!uid || !password) {
                showToast('Please enter both UID and Password', 'error');
                return;
            }
            
            // Show loading state
            loadingEl.style.display = 'flex';
            resultsEl.innerHTML = '';
            
            try {
                const response = await fetch(`${API_BASE}/token?uid=${encodeURIComponent(uid)}&password=${encodeURIComponent(password)}`);
                const data = await response.json();
                
                if (response.ok) {
                    const card = createResultCard(data);
                    resultsEl.appendChild(card);
                    
                    // Show success message
                    showToast(data.cached ? 
                        'Data retrieved from cache' : 
                        'Data fetched successfully', 
                        'success'
                    );
                    
                    // If there's a token, show a special toast about it
                    if (data.token) {
                        setTimeout(() => {
                            showToast('Token is ready! Click the copy button to copy it.', 'info');
                        }, 1000);
                    }
                } else {
                    showToast(data.detail?.message || 'Authentication failed', 'error');
                }
                
            } catch (error) {
                console.error('Error fetching data:', error);
                showToast('Failed to connect to API. Make sure backend is running.', 'error');
            } finally {
                loadingEl.style.display = 'none';
                passwordInput.value = ''; // Clear password for security
            }
        }

        // Event Listeners
        fetchBtn.addEventListener('click', fetchAccountData);

        // Allow Enter key to submit
        [uidInput, passwordInput].forEach(input => {
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    fetchAccountData();
                }
            });
        });

        refreshCacheBtn?.addEventListener('click', loadCacheStats);

        // Modal event listeners
        modalCloseBtns.forEach(btn => {
            btn.addEventListener('click', closeTokenModal);
        });

        // Click outside modal to close
        tokenModal.addEventListener('click', (e) => {
            if (e.target === tokenModal) {
                closeTokenModal();
            }
        });

        // Modal copy button
        modalCopyBtn.addEventListener('click', () => {
            const token = fullTokenEl.textContent;
            if (token) {
                copyToClipboard(token);
                modalCopyBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                setTimeout(() => {
                    modalCopyBtn.innerHTML = '<i class="fas fa-copy"></i> Copy Token';
                }, 2000);
            }
        });

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            showToast('API Dashboard ready. Welcome to Game Auth API!', 'info');
            
            // Add example credentials placeholder
            uidInput.placeholder = 'e.g., 123456789012';
            passwordInput.placeholder = 'Enter your password';
            
            // Escape key to close modal
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && tokenModal.style.display === 'flex') {
                    closeTokenModal();
                }
            });
        });
    </script>
</body>
</html>
    """
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=5000,
        reload=False,
        workers=1,
        loop="asyncio",
        http="httptools",
        timeout_keep_alive=30
    )
