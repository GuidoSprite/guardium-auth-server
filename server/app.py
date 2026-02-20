import os
import json
import base64
import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from nacl.signing import SigningKey

app = FastAPI(title="Guardium License Activation Server")

# --- Configuration (Set these via Environment Variables in Production) ---
LEMONSQUEEZY_API_KEY = os.getenv("LEMONSQUEEZY_API_KEY", "your_api_key_here")

# We expect the Private Key to be passed as an ENV variable in HEX format for easy hosting
PRIVATE_KEY_HEX = os.getenv("ED25519_PRIVATE_KEY_HEX", "")

class ActivationRequest(BaseModel):
    license_key: str

def canonicalize(payload: dict) -> bytes:
    """Deterministically canonicalizes a JSON dictionary."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode('utf-8')

@app.post("/v1/activate")
async def activate_license(req: ActivationRequest):
    """
    Validates a LemonSqueezy license key and returns an Ed25519 signed JSON license payload.
    """
    if not PRIVATE_KEY_HEX:
        raise HTTPException(status_code=500, detail="Server misconfiguration: Missing Private Key.")

    # 1. Contact LemonSqueezy API to validate the key
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {LEMONSQUEEZY_API_KEY}"
    }
    
    # Official LemonSqueezy License Validation API
    try:
        ls_response = requests.post(
            "https://api.lemonsqueezy.com/v1/licenses/validate",
            headers=headers,
            json={"license_key": req.license_key},
            timeout=10
        )
        ls_data = ls_response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to communicate with LemonSqueezy: {str(e)}")

    if not ls_data.get("valid", False):
         raise HTTPException(status_code=400, detail=ls_data.get("error", "Invalid license key."))

    # 2. Extract Data from LemonSqueezy Response
    meta = ls_data.get("meta", {})
    order_id = meta.get("order_id", "unknown")
    variant_name = meta.get("variant_name", "basic").lower()
    
    # Map LemonSqueezy Variant/Tier to Guardium Tier
    tier = "basic"
    if "smart" in variant_name:
        tier = "smart"
    elif "immune" in variant_name:
        tier = "immune"

    # 3. Fabricate License Payload
    payload = {
        "schema": 1,
        "product": "antivirus_suite",
        "tier": tier,
        "license_id": req.license_key[:8] + "...", # Mask the actual key
        "order_id": str(order_id),
        "expires_at": "2027-12-31T23:59:59Z", # Alternatively, check if it's a subscription on LS
        "nonce": os.urandom(8).hex()
    }

    # 4. Sign Crittografically using Server's Private Ed25519 Key
    try:
        signing_key = SigningKey(bytes.fromhex(PRIVATE_KEY_HEX))
        data_to_sign = canonicalize(payload)
        signature = signing_key.sign(data_to_sign).signature
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to sign license packet.")

    # 5. Return Signed Payload to Client
    return {
        "payload": payload,
        "signature": base64.b64encode(signature).decode('utf-8')
    }

@app.get("/")
def health_check():
    return {"status": "Guardium Auth Bridge Online"}
