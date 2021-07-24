from bson import ObjectId
from pydantic import Field
import uvicorn
from mongoengine import connect
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from starlette import status
from typing import Optional

from models import Users
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import json
from datetime import timedelta, datetime
from jose import jwt
from jose import JWTError, jwt
from mongoengine import Document, StringField, IntField
import uuid
import rsa
from datetime import datetime

start = datetime.today()
app = FastAPI()

connect(db="hubdb3", host="localhost", port=27017)


@app.get("/when")
async def whenStarParty():
    year = 2021
    month = 8
    dd = 29
    now = datetime.today()
    NY = datetime(year, month, dd)
    d = NY - now  # str(d)  '83 days, 2:43:10.517807'
    mm, ss = divmod(d.seconds, 60)
    hh, mm = divmod(mm, 60)
    result = (' {} дней {} часа {} мин {} сек.'.format(d.days, hh, mm, ss))
    return {"до открытия": str(result), "текущая дата": str(now)}


class NewUser(BaseModel):
    username: str
    password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@app.get('/get_all_users')
def get_all_user():
    users = json.loads(Users.objects().to_json())
    return {"users": users}


def get_password_hash(password):
    return pwd_context.hash(password)


@app.get('/run')
def firstMeet():
    ud = uuid.uuid4()
    return {"app_id": ud}


#
# @app.post('/key/{app_id}')
# def keyForLogin(app_id, newuser:NewUser):
#     (bob_pub, bob_priv) = rsa.newkeys(512)
#     message = app_id.encode('utf8')
#     crypto = rsa.encrypt(message, bob_pub)
#     message = rsa.decrypt(crypto, bob_priv)
#     decoded = str(message.decode('utf8'))
#     public_key = str(bob_pub)
#
#     user = Users(private_key=newuser.bob_priv, app_id=newuser.app_id)
#     user.save()
#     return {"public_key": public_key}

@app.post('/sign_up')
def sign_up(new_user: NewUser):
    user = Users(
        username=new_user.username,
        password=get_password_hash(new_user.password)
    )
    user.save()
    return {"message": "new user was sign upped"}


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def auth_user(username, password):
    try:
        user = json.loads(Users.objects.get(username=username).to_json())
        password_check = pwd_context.verify(password, user["password"])
        return password_check
    except Users.DoesNotExist:
        return False


SECRET_KEY = "3aa04e672a768d1b5c87b4c0c0d2156a"
ALGORITHM = "HS256"


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt


@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password

    if auth_user(username, password):
        access_token = create_access_token(
            data={"sub": username}, expires_delta=timedelta(minutes=30)
        )
        return {"username": username, "access_token": access_token}
    else:
        raise HTTPException(status_code=400, detail="Incorrect username or password")


@app.get("/")
def start(token: str = Depends(oauth2_scheme)):
    return {"token": token}


# run server

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    uvicorn.run("main:app", port=8000, host='127.0.0.1', reload=True)
# See PyCharm help at https://www.jetbrains.com/help/pycharm/
