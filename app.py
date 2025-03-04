import os
import httpx
import bcrypt
import datetime
from fastapi import FastAPI, Depends
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models import User, Item, get_db

security = HTTPBearer()

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "your-auth0-domain")
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE", "your-api-audience")
M2M_CLIENT_ID = os.getenv("M2M_CLIENT_ID", "your-m2m-client-id")
ALGORITHMS = ["RS256"]

# Function to verify JWT
async def verify_jwt(token: str) -> dict:
    try:
        header = jwt.get_unverified_header(token)
        jwks_url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
        async with httpx.AsyncClient() as client:
            jwks = (await client.get(jwks_url)).json()

        # Find the correct key
        rsa_key = None
        for key in jwks["keys"]:
            if key["kid"] == header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"],
                }
        if not rsa_key:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Decode the JWT
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=AUTH0_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/",
        )
        return payload
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token") from e

app = FastAPI()

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class ItemCreate(BaseModel):
    name: str

async def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode()

async def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode())

def generate_jwt(user_id: int):
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    payload = {"sub": str(user_id), "exp": expiration}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: AsyncSession = Depends(get_db)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token")

    result = await db.execute(select(User).filter(User.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user
async def get_current_user_or_m2m(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print("Decoded JWT Payload:", payload)  # Debugging

        # If it's a user token
        if "sub" in payload:
            user_id = int(payload["sub"])
            result = await db.execute(select(User).filter(User.id == user_id))
            user = result.scalars().first()
            if not user:
                raise HTTPException(status_code=401, detail="User not found")
            return user  # Regular User Access

        # If it's an M2M App token
        elif "client_id" in payload and payload["client_id"] == M2M_CLIENT_ID:
            return {"m2m": True}  # M2M Service Access

        raise HTTPException(status_code=401, detail="Invalid token format")

    except JWTError as e:
        print("JWT Decode Error:", str(e))  # Debugging
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/register", response_model=TokenResponse)
async def register_user(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.email == user_data.email))
    existing_user = result.scalars().first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_pw = await hash_password(user_data.password)
    new_user = User(email=user_data.email, password_hash=hashed_pw)
    db.add(new_user)
    await db.commit()
    return generate_jwt(new_user.id)

@app.post("/login", response_model=TokenResponse)
async def login(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.email == user_data.email))
    user = result.scalars().first()
    if not user or not await verify_password(user_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return generate_jwt(user.id)

@app.post("/items/")
async def add_item(item_data: ItemCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    new_item = Item(name=item_data.name, owner_id=user.id)
    db.add(new_item)
    await db.commit()
    await db.refresh(new_item)  # Ensure new_item.id is populated
    return {"message": "Item added successfully", "item_id": new_item.id}

@app.get("/items/{item_id}")
async def read_item(
    item_id: int,
    user_or_m2m: dict = Depends(get_current_user_or_m2m),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Item).filter(Item.id == item_id))
    item = result.scalars().first()

    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    # Allow access if it's an M2M request
    # If regular user, check ownership
    if isinstance(user_or_m2m, dict) and user_or_m2m.get("m2m"):
        return item  # M2M Client can read all items

    # Allow access if the user owns the item
    if user_or_m2m.id == item.owner_id:
        return item

    raise HTTPException(status_code=403, detail="Access denied")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", reload=True)