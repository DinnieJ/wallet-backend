from fastapi import FastAPI, Response, Depends
from fastapi.responses import RedirectResponse
import requests
import urllib.parse
import base64
from session import cookie, backend, SessionData
import uuid


COGNITO_APP_CLIENT_ID="1gvhaehnlao5vgvjn12e0vkl8a"
COGNITO_APP_CLIENT_SECRET="ghprl3igmbj4b8874djo5ahogdjujjtv0k8rp4lg68939dc6md8"
AUTH_CALLBACK_URI="http://localhost:5000/callback/"

BASIC_TOKEN = base64.b64encode(f"{COGNITO_APP_CLIENT_ID}:{COGNITO_APP_CLIENT_SECRET}".encode("utf8")).decode("utf8")


app = FastAPI()

@app.get("/health-check")
def healthcheck():
    return {
        "hello": 1
    }

@app.get("/callback")
async def callback_cognito(code: str, response: Response):
    if not code:
        return {
            "fucked": "man"
        }
    params = {
        "grant_type": "authorization_code",
        "client_id": COGNITO_APP_CLIENT_ID,
        "code": code,
        "redirect_uri": AUTH_CALLBACK_URI
    }
    body = f"grant_type=authorization_code&client_id={COGNITO_APP_CLIENT_ID}&code={code}&redirect_uri={AUTH_CALLBACK_URI}"
    data = requests.post(
        url="https://walletclient0c49a695-0c49a695-master.auth.ap-southeast-1.amazoncognito.com/oauth2/token",
        headers={
            "Content-Type": 'application/x-www-form-urlencoded',
            "Authorization": f"Basic {BASIC_TOKEN}",
        },
        data=body
    )
    print(body)
    print(BASIC_TOKEN)

    if data.status_code == 200:
        print(data.json())
        session_uuid = str(uuid.uuid1())
        print(session_uuid)
        resp_json = data.json()
        data = SessionData(access_token=resp_json.get("access_token"), refresh_token=resp_json.get("refresh_token"))
        
        await backend.create(session_uuid, data)
        # cookie.attach_to_response(response, session_uuid)
        return RedirectResponse(f"http://localhost:5173/confirm?session={session_uuid}&code=bullshit")
    else:
        return {
            "info": data.json()
        }
@app.get("/test/{id}")
async def test(id: str):
    # uid = uuid.UUID(id)
    data = await backend.read(id)
    return data

@app.get("/test2/{id}")
async def test(id: str):
    # uid = uuid.UUID(id)
    data = await backend.read(id)
    print(backend.data)
    return backend.data.get(id)
    