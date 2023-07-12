from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from models import Users
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from database import SessionLocal
from starlette import status
from fastapi.security import OAuth2PasswordRequestForm,OAuth2PasswordBearer
from jose import jwt ,JWTError
from datetime import datetime,timedelta

router = APIRouter()

bcrypt_context = CryptContext(schemes=['bcrypt'],deprecated = 'auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl = 'auth/token')


SECRET_KEY = '1f6344dba79111dfed88a9955e288e786f00c63a5832dbdb75a0ab273ac79233'
ALGORITHM = 'HS256'

router = APIRouter(
    prefix = '/auth',
    tags = ['auth']
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session,Depends(get_db)]

class CreateUserRequest(BaseModel):
    username: str
    email:str
    first_name:str
    last_name:str
    password:str
    role:str
    



@router.post("/auth/",status_code=status.HTTP_201_CREATED)
async def create_user(db:db_dependency,create_user_request:CreateUserRequest):
    create_user__model = Users(
        email = create_user_request.email,
        username = create_user_request.username,
        first_name = create_user_request.first_name,
        last_name=create_user_request.last_name,
        role = create_user_request.role,
        hashed_password = bcrypt_context.hash(create_user_request.password),
        is_active = True)
    db.add(create_user__model)
    db.commit()

def create_access_token(username:str,user_id:int,expires_delta:timedelta):
    encode = {'sub':username ,'id':user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({'exp':expires})
    return jwt.encode(encode,SECRET_KEY,algorithm=ALGORITHM)

async def get_current_user(token:Annotated[str,Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms = [ALGORITHM])
        username: str = payload.get('sub') #type:ignore
        user_id: int = payload.get('id') # type: ignore
        if username is None or user_id is None:
            raise HTTPException(status_code = status.HTTP_401_UNAUTHORIZED,detail='Could not validate User')
        return {'username':username,'id':user_id}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail='could not validate user')
        
        
    


@router.post("/token")
async def login_for_access_token(form_data:Annotated[OAuth2PasswordRequestForm,Depends()],db: db_dependency):
    user = authenticate_User(form_data.username,form_data.password,db)
    if not user:
        raise HTTPException(status_code = status.HTTP_401_UNAUTHORIZED,detail='Could not validate User')
    token = create_access_token(user.username,user.id,timedelta(minutes = 20))
    return {'access_token': token, 'token_type': 'bearer'}

def authenticate_User(username:str,password:str,db):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password,user.hashed_password):
        return False
    return user
