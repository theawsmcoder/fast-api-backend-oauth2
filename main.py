from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from passlib.hash import bcrypt
import jwt

from tortoise import fields
from tortoise.models import Model
from tortoise.contrib.fastapi import register_tortoise
from tortoise.contrib.pydantic import pydantic_model_creator

from decouple import config


JWT_SECRET = config("secret")
HASH_ALGORITHM = config("algorithm")


app = FastAPI()


class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique=True)
    password_hash = fields.CharField(128)

    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)

register_tortoise(
    app,
    db_url='sqlite://db.sqlite3',
    modules={'models': ['main']},
    generate_schemas=True,
    add_exception_handlers=True
)


User_PydanticModel = pydantic_model_creator(User, name='User');
UserIn_PydanticModel = pydantic_model_creator(User, name='UserIn', exclude_readonly=True)



@app.post('/signup', response_model = User_PydanticModel)
async def signup(user: UserIn_PydanticModel):
    temp_tortoise_user = User(username=user.username, password_hash=bcrypt.hash(user.password_hash))
    await temp_tortoise_user.save()
    return await User_PydanticModel.from_tortoise_orm(temp_tortoise_user)


oauth2_schema = OAuth2PasswordBearer(tokenUrl='token')


async def authenticate_user(username: str, password: str):
    user = await User.get(username=username)
    if not user:
        return False
    if not user.verify_password(password=password):
        return False
    return user

@app.post('/token')
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid username or password'
        )
    user_obj = await User_PydanticModel.from_tortoise_orm(user)
    payload = {'id':user_obj.dict().get('id'), 'username':user_obj.dict().get('username')}
    token = jwt.encode(payload, JWT_SECRET, algorithm=HASH_ALGORITHM)
    return {'access_token': token, 'token_type': 'bearer'}

# this is to check if current user exists in the database. we can use it to validate the token, need to modify the code a little bit
async def get_current_user(token: str = Depends(oauth2_schema)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=HASH_ALGORITHM)
        user = await User.get(id=payload.get('id'))
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid username or password'
        )
    return await User_PydanticModel.from_tortoise_orm(user)

@app.get('/users/current_user')
async def get_user(user: User_PydanticModel = Depends(get_current_user)):
    return user
    

@app.route('/signin')
def signin(token: str = Depends(oauth2_schema)):
    return {'token': token}


