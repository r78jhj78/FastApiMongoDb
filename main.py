import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, Field, EmailStr
from pymongo import MongoClient
from passlib.context import CryptContext
import jwt
from dotenv import load_dotenv
from fastapi import Query

load_dotenv()

# ---------------------------
# Config
# ---------------------------
SECRET_KEY = os.getenv("JWT_SECRET", "cambiame_por_una_clave_segura_en_prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 días

MONGO_CONN = os.getenv("MONGO_URL") or os.getenv("MONGO_PUBLIC_URL")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME")
if not MONGO_CONN:
    raise RuntimeError("No se encontró MONGO_URL ni MONGO_PUBLIC_URL en variables de entorno")
if not MONGO_DB_NAME:
    raise RuntimeError("No se encontró MONGO_DB_NAME en variables de entorno")

# ---------------------------
# MongoDB
# ---------------------------
client = MongoClient(MONGO_CONN)
db = client[MONGO_DB_NAME]

users_col = db["users"]
recipes_col = db["recipes"]
providers_col = db["providers"]

# ---------------------------
# Security utilities
# ---------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def hash_password(password: str) -> str:
    max_length = 72
    # Truncar la contraseña si excede 72 bytes en UTF-8
    encoded = password.encode('utf-8')
    if len(encoded) > max_length:
        encoded = encoded[:max_length]
        password = encoded.decode('utf-8', 'ignore')  # Ignorar si corta caracteres multibyte
    print(f"Hashing password: '{password}' Length in bytes: {len(password.encode('utf-8'))}")
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

# ---------------------------
# Pydantic models
# ---------------------------
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3)
    email: Optional[EmailStr] = None
    password: str = Field(..., min_length=6)

class UserOut(BaseModel):
    id: str
    username: str
    email: Optional[EmailStr] = None
    role: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class RoleChangeRequest(BaseModel):
    new_role: str  # "chef" o "proveedor"

class RecipeCreate(BaseModel):
    title: str
    ingredients: list[str]
    steps: list[str]
    chef_username: Optional[str] = None

class ProviderCreate(BaseModel):
    name: str
    contact: str
    products: list[str]
    location: Optional[str] = None

# ---------------------------
# FastAPI app
# ---------------------------
app = FastAPI(title="Cam Cook - API (FastAPI + MongoDB)")

# ---------------------------
# Helpers: user CRUD + auth
# ---------------------------
def get_user_by_username(username: str):
    return users_col.find_one({"username": username})

def create_user(username: str, email: Optional[str], password: str):
    if get_user_by_username(username):
        raise HTTPException(400, "Usuario ya existe")
    hashed = hash_password(password)
    user_doc = {
        "_id": username,
        "username": username,
        "email": email,
        "password": hashed,
        "role": "usuario",
        "created_at": datetime.utcnow().isoformat()
    }
    users_col.insert_one(user_doc)
    return user_doc

def authenticate_user(username: str, password: str):
    user = get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user["password"]):
        return None
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(401, "Token inválido (no sub)")
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(401, "Usuario no existe")
    return user

# ---------------------------
# Auth endpoints
# ---------------------------
@app.post("/auth/register", response_model=UserOut)
def register(user: UserCreate):
    print("👉 Recibido:", user.dict())
    try:
        doc = create_user(user.username, user.email, user.password)
        return UserOut(
            id=doc["_id"],
            username=doc["username"],
            email=doc.get("email"),
            role=doc["role"]
        )
    except Exception as e:
        print("❌ Error en /auth/register:", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/auth/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Usuario o contraseña inválidos")
    token = create_access_token({"sub": user["username"], "role": user["role"]})
    return TokenResponse(access_token=token)

# ---------------------------
# User endpoints
# ---------------------------
@app.get("/users/me", response_model=UserOut)
def me(current_user=Depends(get_current_user)):
    return UserOut(
        id=current_user["_id"],
        username=current_user["username"],
        email=current_user.get("email"),
        role=current_user["role"]
    )

@app.post("/users/upgrade", response_model=UserOut)
def upgrade_role(req: RoleChangeRequest, current_user=Depends(get_current_user)):
    new_role = req.new_role.lower()
    if new_role not in ("chef", "proveedor"):
        raise HTTPException(400, "Rol inválido. Solo 'chef' o 'proveedor'")

    # Actualizar rol del usuario
    users_col.update_one({"_id": current_user["_id"]}, {"$set": {"role": new_role}})
    updated = get_user_by_username(current_user["username"])
    return UserOut(
        id=updated["_id"],
        username=updated["username"],
        email=updated.get("email"),
        role=updated["role"]
    )

# ---------------------------
# Recipes endpoints
# ---------------------------
@app.post("/recipes")
def create_recipe(recipe: RecipeCreate, current_user=Depends(get_current_user)):
    if current_user["role"] not in ("chef", "admin"):
        raise HTTPException(403, "Solo chefs (o admin) pueden subir recetas")
    doc = {
        "_id": f"{recipe.title}-{datetime.utcnow().timestamp()}",
        "title": recipe.title,
        "ingredients": recipe.ingredients,
        "steps": recipe.steps,
        "chef": recipe.chef_username or current_user["username"],
        "approved": False,  # Pendiente aprobación admin
        "created_at": datetime.utcnow().isoformat()
    }
    recipes_col.insert_one(doc)
    return {"status": "ok", "recipe_id": doc["_id"], "approved": doc["approved"]}

@app.get("/recipes")
def list_recipes(q: Optional[str] = None):
    query = {}
    if q:
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"ingredients": {"$regex": q, "$options": "i"}}
        ]
    docs = list(recipes_col.find(query, {"_id": 1, "title": 1, "chef": 1, "approved": 1}))
    return docs

# ---------------------------
# Providers endpoints
# ---------------------------
@app.post("/providers")
def create_provider(provider: ProviderCreate, current_user=Depends(get_current_user)):
    if current_user["role"] != "proveedor":
        raise HTTPException(403, "Solo usuarios con rol 'proveedor' pueden crear proveedor")
    doc = {
        "_id": f"prov-{provider.name}-{datetime.utcnow().timestamp()}",
        "name": provider.name,
        "contact": provider.contact,
        "products": provider.products,
        "location": provider.location,
        "owner": current_user["_id"],
        "created_at": datetime.utcnow().isoformat()
    }
    providers_col.insert_one(doc)
    return {"status": "ok", "provider_id": doc["_id"]}

@app.get("/providers")
def list_providers():
    docs = list(providers_col.find({}, {"_id": 1, "name": 1, "products": 1, "contact": 1}))
    return docs

# ---------------------------
# Startup / Shutdown
# ---------------------------
@app.on_event("startup")
def startup():
    users_col.create_index("username", unique=True)
    print("✅ API arrancada. Conexión a Mongo OK.")

@app.on_event("shutdown")
def shutdown():
    client.close()
    print("🔴 Conexión Mongo cerrada.")

@app.get("/search")
def global_search(q: str = Query(..., description="Término de búsqueda")):
    search_query = {"$regex": q, "$options": "i"}

    # Buscar en recetas
    recipe_query = {
        "$or": [
            {"title": search_query},
            {"ingredients": search_query},
            {"chef": search_query},
        ]
    }
    recipes = list(recipes_col.find(recipe_query, {"_id": 1, "title": 1, "chef": 1, "approved": 1}))

    # Buscar en proveedores
    provider_query = {
        "$or": [
            {"name": search_query},
            {"products": search_query},
        ]
    }
    providers = list(providers_col.find(provider_query, {"_id": 1, "name": 1, "products": 1, "contact": 1}))

    return {
        "recipes": recipes,
        "providers": providers
    }