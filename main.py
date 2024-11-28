from datetime import datetime, timedelta, timezone
from typing import Annotated
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings
from passlib.context import CryptContext
import logging

import jwt
from jwt.exceptions import InvalidTokenError

# to get a string like this run:
# openssl rand -hex 32
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1


class TokenData(BaseModel):
    username: str | None = None


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    token: Annotated[HTTPAuthorizationCredentials, Depends(HTTPBearer())]
):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token.credentials, settings.secret_key, algorithms=[ALGORITHM]
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = await db.user.find_one({"username": token_data.username})
    if user is None:
        raise credentials_exception
    return user


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration settings
class Settings(BaseSettings):
    mongodb_uri: str
    secret_key: str
    debug: bool = False

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# Initialize FastAPI app
app = FastAPI(debug=settings.debug)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables for MongoDB client and database
client = None
db = None


@app.on_event("startup")
async def create_indexes():
    global client, db
    try:
        client = AsyncIOMotorClient(settings.mongodb_uri)
        db = client.get_database("fastapi_project")
        await db.user.create_index("username", unique=True)
        # Check MongoDB connection
        await db.command("ping")
        logger.info("Connected to MongoDB and created indexes successfully")
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        raise RuntimeError("Failed to connect to MongoDB")


@app.on_event("shutdown")
async def shutdown_event():
    if client:
        client.close()
        logger.info("MongoDB connection closed")


@app.get("/")
def read_root():
    return {"message": "Welcome to the FastAPI application"}


@app.get("/ping/mongodb")
async def ping_mongodb():
    try:
        await db.command("ping")
        return {"message": "Successfully connected to MongoDB!"}
    except Exception as e:
        logger.error(f"MongoDB ping failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to connect to MongoDB")


# User model for input validation
class User(BaseModel):
    username: str = Field(
        ...,
        min_length=6,
        max_length=20,
        pattern="^[a-z][a-z0-9]*$",
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )
    password: str = Field(
        ...,
        min_length=6,
        max_length=20,
    )

    @model_validator(mode="before")
    def validate_password(cls, values):
        password = values.get("password")
        if not password:
            raise ValueError("Password is required.")

        # Check for at least one digit
        if not any(char.isdigit() for char in password):
            raise ValueError("Password must contain at least one digit.")

        # Check for at least one special character
        if not any(char in "!@#$%^&*()-_+=" for char in password):
            raise ValueError("Password must contain at least one special character.")

        # Check for at least one letter
        if not any(char.isalpha() for char in password):
            raise ValueError("Password must contain at least one letter.")

        return values


# Response model for successful registration
class UserResponse(BaseModel):
    id: str
    username: str
    name: str


class RegisterResponse(BaseModel):
    message: str
    user: UserResponse


@app.post("/users/register", response_model=RegisterResponse)
async def user_register(user: User):
    try:
        # Check if username already exists
        existing_user = await db.user.find_one({"username": user.username})
        if existing_user:
            raise ValueError("Username already exists")

        # Hash the password and store user
        hashed_password = hash_password(user.password)
        user_data = user.dict()
        user_data["password"] = hashed_password
        result = await db.user.insert_one(user_data)

        # Retrieve the created user
        created_user = await db.user.find_one({"_id": result.inserted_id})
        return RegisterResponse(
            message="User registered successfully",
            user=UserResponse(
                id=str(created_user["_id"]),
                username=created_user["username"],
                name=created_user["name"],
            ),
        )
    except ValueError as ve:
        raise HTTPException(status_code=422, detail=str(ve))
    except Exception as e:
        logger.error(f"Unexpected error during user registration: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


class LoginResponse(BaseModel):
    message: str
    user: UserResponse
    token: str


class LoginModel(BaseModel):
    username: str = Field(..., min_length=6, max_length=20, pattern="^[a-z][a-z0-9]*$")
    password: str = Field(..., min_length=6, max_length=20)


@app.post("/users/login", response_model=LoginResponse)
async def user_login(login_model: LoginModel):
    try:
        user = await db.user.find_one({"username": login_model.username})
        if not user:
            raise ValueError("Username or password is not correct")
        if not verify_password(login_model.password, user["password"]):
            raise ValueError("Username or password is not correct")
        ## create token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["username"]}, expires_delta=access_token_expires
        )
        return LoginResponse(
            message="User logined successfully",
            user=UserResponse(
                id=str(user["_id"]), username=user["username"], name=user["name"]
            ),
            token=access_token,
        )
    except ValueError as ve:
        raise HTTPException(status_code=401, detail=str(ve))
    except Exception as e:
        logger.error(f"Unexpected error during user login: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.get("/users/me/", response_model=UserResponse)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_user)],
):
    return UserResponse(
        id=str(current_user["_id"]),
        username=current_user["username"],
        name=current_user["name"],
    )
