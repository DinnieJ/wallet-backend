from io import BytesIO
import random
import string
from fastapi import FastAPI, Response, Depends
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import pyotp
import qrcode
import base64
import requests
import urllib.parse
import base64

from sqlalchemy import select
from session import cookie, backend, SessionData
import uuid
from model import User
from jose import jwt
from db import SessionLocal
from fastapi.middleware.cors import CORSMiddleware

COGNITO_APP_CLIENT_ID = "1gvhaehnlao5vgvjn12e0vkl8a"
COGNITO_APP_CLIENT_SECRET = "ghprl3igmbj4b8874djo5ahogdjujjtv0k8rp4lg68939dc6md8"
AUTH_CALLBACK_URI = "http://localhost:5000/callback/"

BASIC_TOKEN = base64.b64encode(
    f"{COGNITO_APP_CLIENT_ID}:{COGNITO_APP_CLIENT_SECRET}".encode("utf8")
).decode("utf8")


def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return "".join(random.choice(chars) for _ in range(size))

def generate_qr_code_base64(reference):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(reference)
    qr.make(fit=True)
    img = qr.make_image(fillc_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf)
    return base64.b64encode(buf.getvalue())


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health-check")
def healthcheck():
    return {"hello": 1}


def create_or_get_user(email, name):
    with SessionLocal() as session:
        user = session.query(User).filter_by(email=email).first()
        if not user:
            new_user = User(email=email, name=name, otp_setup=False)
            session.add(new_user)
            session.commit()
            session.refresh(new_user)
            return True, new_user
        return False, user
def get_user(email):
     with SessionLocal() as session:
        user = session.query(User).filter_by(email=email).first()
        return user
    
def confirm_user_secret(email, secret):
    with SessionLocal() as session:
        user = session.query(User).filter_by(email=email).first()
        if not user:
            return
        user.secret = secret
        user.otp_setup = True
        session.commit()
        session.refresh(user)

@app.get("/callback")
async def callback_cognito(code: str, response: Response):
    if not code:
        return {"fucked": "man"}
    params = {
        "grant_type": "authorization_code",
        "client_id": COGNITO_APP_CLIENT_ID,
        "code": code,
        "redirect_uri": AUTH_CALLBACK_URI,
    }
    body = f"grant_type=authorization_code&client_id={COGNITO_APP_CLIENT_ID}&code={code}&redirect_uri={AUTH_CALLBACK_URI}"
    data = requests.post(
        url="https://walletclient0c49a695-0c49a695-master.auth.ap-southeast-1.amazoncognito.com/oauth2/token",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {BASIC_TOKEN}",
        },
        data=body,
    )

    if data.status_code == 200:
        j_data = data.json()
        id_token = j_data.get("id_token")
        decoded_id_token = jwt.decode(
            id_token,
            key=None,
            options={
                "verify_signature": False,
                "verify_aud": False,
                "verify_iat": False,
                "verify_exp": True,
                "verify_nbf": False,
                "verify_iss": True,
                "verify_sub": True,
                "verify_jti": True,
                "verify_at_hash": False,
            },
        )
        session_uuid = str(uuid.uuid1())
        created, user = create_or_get_user(
            decoded_id_token.get("email"), decoded_id_token.get("cognito:username")
        )
        resp_json = data.json()
        data = SessionData(
            access_token=resp_json.get("access_token"),
            refresh_token=resp_json.get("refresh_token"),
            email=user.email,
            first_time_login=not user.otp_setup,
            tmp_secret=None
        )

        await backend.create(session_uuid, data)

        return RedirectResponse(
            f"http://localhost:5173/confirm?session={session_uuid}&code=bullshit"
        )
    else:
        return {"info": data.json()}


@app.get("/qr/{session}")
async def qr(session: str):
    session_data = await backend.data.get(session)
    pass


def create_base64_otpauth(secret, email):
    otp_url = f"otpauth://totp/Wallet:{email}?secret={secret}&issuer=Wallet"
    import qrcode
    qr = qrcode.make(otp_url)
    

@app.get("/verify/{session}")
async def verify(session: str):
    data = backend.data.get(session)
    if data.first_time_login:
        secret = id_generator(16)
        base32str = base64.b32encode(secret.encode("utf-8")).decode("utf-8")
        otp_url = (
            f"otpauth://totp/Wallet:{data.email}?secret={base32str}&issuer=Wallet&algorithm=SHA1&digits=6&period=30"
        )
        b64_qr = f"{generate_qr_code_base64(otp_url).decode('utf-8')}"
        data.tmp_secret = base32str
        await backend.update(session, data=data)
        return {
            "challenge": "FIRST_TIME_LOGIN",
            "qr": b64_qr
        }
    else:
        return {
            "challenge": "VERIFY_TOTP",
        }

class BodyOtp(BaseModel):
    code: str
    session: str
    
@app.post("/setup-otp")
def setup_otp(body: BodyOtp):
    code = body.code
    session_data = backend.data.get(body.session)
    secret = session_data.tmp_secret
    totp = pyotp.TOTP(secret)
    success = False
    print(body.code, totp.now())
    if totp.now() == code:
        confirm_user_secret(session_data.email, secret)
        success = True
    return {
        "success": success
    }

@app.post("/verify-totp")
def verify_totp(body: BodyOtp):
    session_data = backend.data.get(body.session)
    user = get_user(email=session_data.email)
    totp = pyotp.TOTP(user.secret)
    return {
        "success": totp.now() == body.code
    }