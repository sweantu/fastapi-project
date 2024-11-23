from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import FastAPI, HTTPException

from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from passlib.context import CryptContext


class Settings(BaseSettings):
    mongodb_uri: str
    secret_key: str
    debug: bool = False

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def create_indexes():
    global client
    client = AsyncIOMotorClient(settings.mongodb_uri)
    global db
    db = client.get_database("fastapi_project")
    await db.user.create_index("username", unique=True)
    print("Server starts successfully")


@app.on_event("shutdown")
async def shutdown_event():
    client.close()
    print("Server closes successfully")


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/ping/mongodb")
async def ping_mongodb():
    try:
        await db.command("ping")
        return {
            "message": "Pinged your deployment. You successfully connected to MongoDB!"
        }
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")


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

    # @field_validator("password")
    # def validate_password(cls, password: str) -> str:
    # if len(password) < 8:
    #     raise HTTPException(
    #         status_code=422, detail="Password must be at least 8 characters long."
    #     )
    # if not any(char.isdigit() for char in password):
    #     raise HTTPException(
    #         status_code=422, detail="Password must contains at least one number."
    #     )
    # if not any(char.isupper() for char in password):
    #     raise HTTPException(
    #         status_code=422,
    #         detail="Password must contain at least one uppercase letter.",
    #     )
    # if not any(char in "!@#$%^&*()-_+=" for char in password):
    #     raise HTTPException(
    #         status_code=422,
    #         detail="Password must contain at least one special character.",
    #     )
    # return hash_password(password)


class UserResponse(BaseModel):
    id: str
    username: str
    name: str


class RegisterResponse(BaseModel):
    message: str
    user: UserResponse


@app.post("/users/register", response_model=RegisterResponse)
async def user_register(user_model: User):
    try:
        existing_user = await db.user.find_one({"username": user_model.username})
        if existing_user:
            raise ValueError("Username already exists")
        user_model.password = hash_password(user_model.password)
        result = await db.user.insert_one(user_model.model_dump())
        user = await db.user.find_one({"_id": result.inserted_id})
        return RegisterResponse(
            message="User registered successfully",
            user=UserResponse(
                id=str(user["_id"]), username=user["username"], name=user["name"]
            ),
        )
    except ValueError as ve:
        raise HTTPException(status_code=422, detail=str(ve))
    except Exception as e:
        print(f"Error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
