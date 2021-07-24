# 1. Было бы круто если бы все необходимые зависимости хранились в файле pip-requiments.txt
#    Тогда любой кто будет работать с кодом сможет легко установить их командой pip3 install pip-requiments.txt 
#    И не париться с зависимостями
# 2. Не забывай оставлять комментарии к нетипичному коду, лучше потратить 20 секунд на комментарий сейчас
#    Чем завтра 20 минут вспоминать как работает код. Но не стоит перебарщивать с комментариями и не стоит
#    Писать что то вроде Кирпич # Это кирпич
#    Хорошей практикой комментирования являеться обьяснения в стиле "почему это здесь?", а не "что это?" 
# 3. Не забудь позже добавить Тесты и Логи
# 4. Приятного кодинга!


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

# Можем вынести в Константы все вроде числовых значений/портов/ip адресов/имен баз и т.д. в отдельный 
# конфигурационный файл и добавить .gitignore. Это повышает безопасность кода и упрощает конфигурацию    
connect(db="hubdb3", host="localhost", port=27017)

# Нарушение CodeStyle - именования функций
@app.get("/when")
async def whenStarParty():
    # Так же можно вынести в конфигурационный файл, так как удобней будет изменять уже по ходу выполнения
    year = 2021
    month = 8
    dd = 29
    now = datetime.today()
    NY = datetime(year, month, dd)
    d = NY - now  # str(d)  '83 days, 2:43:10.517807'
    mm, ss = divmod(d.seconds, 60)
    hh, mm = divmod(mm, 60)
    # Не желательно использовать русские символы и кириллицу в основном коде
    # Здесь нужно возвращать обычный формат даты  hh:mm:ss dd.MMMM.yy 
    # Преобразование в нужную форму это уже проблема клиента
    result = (' {} дней {} часа {} мин {} сек.'.format(d.days, hh, mm, ss))
    return {"до открытия": str(result), "текущая дата": str(now)}

# ???
# Нам стоит вынести это в отдельный файл
class NewUser(BaseModel):
    username: str
    password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Это временная функция?
# Если да, то помечай их что бы не забыть потом и 
# не оставить дыры в безопасности
@app.get('/get_all_users')
def get_all_user():
    users = json.loads(Users.objects().to_json())
    return {"users": users}


def get_password_hash(password):
    return pwd_context.hash(password)

# Нарушение Code Style в именование функции - first_meet
# Функцию можно сделать ассинхронной, так как процесс генерации uuid занимает много времени
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
    # Тут стоит не забыть добавить обработку исключений, 
    # На случаи если БД не сможет обработать запрос или задержка в сети не доставит запрос к БД
    # клиенту может прийти уведомление о успешной регистрации которой не произошло
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

# Куда? В конфиг файл)
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
    # Все что приходит из вне
    # Обязательно приводим к типу и оборачиваем в try на случай если пользователь попытается отправить 
    # что то непридвиденное, или баг со стороны фронта не отрпавит лишнего
    # Эту проверку можно вынести в сторонюю бибиблиотеку
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
