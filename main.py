# from fastapi import FastAPI, Depends, HTTPException, status
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from typing import Optional, List
# from jose import JWTError, jwt
# from pydantic import BaseModel
# from passlib.context import CryptContext
# from datetime import datetime, timedelta

# # Simulación de base de datos (reemplazar con DB real)
# fake_users_db = {}
# fake_recipes_db = []
# fake_proveedores_db = []

# # App
# app = FastAPI()

# # Seguridad
# SECRET_KEY = "secreto_super_seguro"
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# # Modelos

# class User(BaseModel):
#     username: str
#     full_name: Optional[str] = None
#     password: str
#     role: str  # admin, cocinero, usuario, proveedor

# class UserInDB(User):
#     hashed_password: str

# class Token(BaseModel):
#     access_token: str
#     token_type: str

# class Recipe(BaseModel):
#     id: int
#     title: str
#     ingredients: List[str]
#     author: str
#     approved: bool = False

# class Proveedor(BaseModel):
#     username: str
#     alimento: str
#     telefono: str

# # Utilidades

# def verify_password(plain_password, hashed_password):
#     return pwd_context.verify(plain_password, hashed_password)

# def get_password_hash(password):
#     return pwd_context.hash(password)

# def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# def get_user(username: str):
#     return fake_users_db.get(username)

# def authenticate_user(username: str, password: str):
#     user = get_user(username)
#     if not user or not verify_password(password, user["hashed_password"]):
#         return None
#     return UserInDB(**user)

# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     credentials_exception = HTTPException(
#         status_code=401,
#         detail="No se pudo validar las credenciales",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise credentials_exception
#     except JWTError:
#         raise credentials_exception
#     user = get_user(username)
#     if user is None:
#         raise credentials_exception
#     return UserInDB(**user)

# async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
#     return current_user

# def require_role(role: str):
#     async def _role_dep(user: UserInDB = Depends(get_current_active_user)):
#         if user.role != role:
#             raise HTTPException(status_code=403, detail=f"Solo para {role}s")
#         return user
#     return _role_dep

# # Endpoints

# @app.post("/register", response_model=Token)
# def register(user: User):
#     if user.username in fake_users_db:
#         raise HTTPException(status_code=400, detail="Usuario ya existe")
#     hashed = get_password_hash(user.password)
#     fake_users_db[user.username] = {
#         "username": user.username,
#         "full_name": user.full_name,
#         "role": user.role,
#         "hashed_password": hashed
#     }
#     access_token = create_access_token(data={"sub": user.username})
#     return {"access_token": access_token, "token_type": "bearer"}

# @app.post("/token", response_model=Token)
# async def login(form_data: OAuth2PasswordRequestForm = Depends()):
#     user = authenticate_user(form_data.username, form_data.password)
#     if not user:
#         raise HTTPException(status_code=400, detail="Credenciales incorrectas")
#     access_token = create_access_token(data={"sub": user.username})
#     return {"access_token": access_token, "token_type": "bearer"}

# @app.post("/recetas/crear", dependencies=[Depends(require_role("cocinero"))])
# def crear_receta(receta: Recipe, user: UserInDB = Depends(get_current_active_user)):
#     receta.id = len(fake_recipes_db) + 1
#     receta.author = user.username
#     fake_recipes_db.append(receta)
#     return {"mensaje": "Receta creada. Esperando aprobación.", "receta": receta}

# @app.get("/recetas", response_model=List[Recipe])
# def ver_recetas():
#     return [r for r in fake_recipes_db if r.approved]

# @app.get("/recetas/pendientes", dependencies=[Depends(require_role("admin"))])
# def recetas_pendientes():
#     return [r for r in fake_recipes_db if not r.approved]

# @app.post("/recetas/aprobar/{receta_id}", dependencies=[Depends(require_role("admin"))])
# def aprobar_receta(receta_id: int):
#     for r in fake_recipes_db:
#         if r.id == receta_id:
#             r.approved = True
#             return {"mensaje": "Receta aprobada"}
#     raise HTTPException(status_code=404, detail="Receta no encontrada")

# @app.post("/proveedor/subir", dependencies=[Depends(require_role("proveedor"))])
# def subir_proveedor(info: Proveedor):
#     fake_proveedores_db.append(info)
#     return {"mensaje": "Proveedor registrado", "data": info}

# @app.get("/proveedores", response_model=List[Proveedor])
# def listar_proveedores():
#     return fake_proveedores_db



#probando el fastApi

# from database import engine
# import models
# from fastapi import Depends
# from sqlalchemy.orm import Session
# from database import SessionLocal
# from fastapi import FastAPI

# app = FastAPI()
# models.Base.metadata.create_all(bind=engine)

# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()

# @app.get("/")
# def root():
#     return {"message": "Bienvenido a la API de CamCook"}

# @app.get("/usuarios")
# def obtener_usuarios(db: Session = Depends(get_db)):
#     return db.query(models.User).all()

# from database import engine
# import models
# from fastapi import Depends
# from sqlalchemy.orm import Session
# from database import SessionLocal
# from fastapi import FastAPI
# from models import User
# from passlib.context import CryptContext
# from sqlalchemy.exc import IntegrityError

# app = FastAPI()


# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()

# @app.get("/")
# def read_root():
#     return {"message": "Bienvenido a la API de CamCook"}

# @app.post("/register")
# def register_user(username: str, password: str, role: str, db: Session = Depends(get_db)):
#     hashed_password = pwd_context.hash(password)
#     user = User(username=username, hashed_password=hashed_password, role=role)
#     db.add(user)
#     db.commit()
#     db.refresh(user)
#     return {"message": "Usuario creado", "user": user.username}

# @app.get("/usuarios")
# def obtener_usuarios(db: Session = Depends(get_db)):
#     return db.query(User).all()

# @app.on_event("startup")
# def crear_usuarios_de_prueba():
#     db = SessionLocal()
#     try:
#         usuarios_prueba = [
#             {"username": "chef1", "password": "1234", "role": "cocinero"},
#             {"username": "user1", "password": "1234", "role": "usuario"},
#             {"username": "proveedor1", "password": "1234", "role": "proveedor"},
#             {"username": "admin1", "password": "adminpass", "role": "admin"},
#         ]

#         for u in usuarios_prueba:
#             # Verificamos si ya existe
#             if not db.query(User).filter_by(username=u["username"]).first():
#                 hashed = pwd_context.hash(u["password"])
#                 nuevo_usuario = User(username=u["username"], hashed_password=hashed, role=u["role"])
#                 db.add(nuevo_usuario)
#         db.commit()
#     except IntegrityError:
#         db.rollback()
#     finally:
#         db.close()

# main.py
# import os
# from datetime import datetime, timedelta
# from typing import Optional
# from fastapi import FastAPI, HTTPException, Depends, status
# from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
# from pydantic import BaseModel, Field, EmailStr
# from pymongo import MongoClient
# from passlib.context import CryptContext
# import jwt
# from dotenv import load_dotenv
# import os

# load_dotenv()

# # ---------------------------
# # Config
# # ---------------------------
# SECRET_KEY = os.getenv("JWT_SECRET", "cambiame_por_una_clave_segura_en_prod")
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 días

# # Selección de URL: dentro de Railway usar MONGO_URL, local use MONGO_PUBLIC_URL
# MONGO_CONN = os.getenv("MONGO_URL") or os.getenv("MONGO_PUBLIC_URL")
# if not MONGO_CONN:
#     raise RuntimeError("No se encontró MONGO_URL ni MONGO_PUBLIC_URL en variables de entorno")

# # ---------------------------
# # MongoDB
# # ---------------------------
# client = MongoClient(MONGO_CONN)
# db = client.get_database()  # usa la DB por defecto de la URL o la que proporcione Mongo URI

# users_col = db["users"]
# recipes_col = db["recipes"]
# providers_col = db["providers"]

# # ---------------------------
# # Security utilities
# # ---------------------------
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# def hash_password(password: str) -> str:
#     return pwd_context.hash(password)

# def verify_password(plain: str, hashed: str) -> bool:
#     return pwd_context.verify(plain, hashed)

# def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# def decode_token(token: str):
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         return payload
#     except jwt.ExpiredSignatureError:
#         raise HTTPException(status_code=401, detail="Token expirado")
#     except jwt.PyJWTError:
#         raise HTTPException(status_code=401, detail="Token inválido")

# # ---------------------------
# # Pydantic models
# # ---------------------------
# class UserCreate(BaseModel):
#     username: str = Field(..., min_length=3)
#     email: Optional[EmailStr] = None
#     password: str = Field(..., min_length=6)

# class UserOut(BaseModel):
#     id: str
#     username: str
#     email: Optional[EmailStr] = None
#     role: str

# class TokenResponse(BaseModel):
#     access_token: str
#     token_type: str = "bearer"

# class RoleChangeRequest(BaseModel):
#     new_role: str  # "chef" o "proveedor"

# # ---------------------------
# # FastAPI app
# # ---------------------------
# app = FastAPI(title="Cam Cook - API (FastAPI + MongoDB)")

# # ---------------------------
# # Helpers: user CRUD + auth
# # ---------------------------
# def get_user_by_username(username: str):
#     return users_col.find_one({"username": username})

# def get_user_by_id_hex(id_hex: str):
#     return users_col.find_one({"_id": id_hex})  # usamos id string simple

# def create_user(username: str, email: Optional[str], password: str):
#     if get_user_by_username(username):
#         raise HTTPException(400, "Usuario ya existe")
#     hashed = hash_password(password)
#     # ID simple: usar username como _id para simplicidad. En prod use ObjectId.
#     user_doc = {
#         "_id": username,  # simple único
#         "username": username,
#         "email": email,
#         "password": hashed,
#         "role": "usuario",   # <-- comportamiento solicitado: siempre "usuario" al crear
#         "created_at": datetime.utcnow().isoformat()
#     }
#     users_col.insert_one(user_doc)
#     return user_doc

# def authenticate_user(username: str, password: str):
#     user = get_user_by_username(username)
#     if not user:
#         return None
#     if not verify_password(password, user["password"]):
#         return None
#     return user

# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     payload = decode_token(token)
#     username = payload.get("sub")
#     if not username:
#         raise HTTPException(401, "Token inválido (no sub)")
#     user = get_user_by_username(username)
#     if not user:
#         raise HTTPException(401, "Usuario no existe")
#     return user

# # ---------------------------
# # Auth endpoints
# # ---------------------------
# @app.post("/auth/register", response_model=UserOut)
# def register(user: UserCreate):
#     """
#     Registro: siempre crea el usuario con role = 'usuario'.
#     """
#     doc = create_user(user.username, user.email, user.password)
#     return UserOut(
#         id=doc["_id"],
#         username=doc["username"],
#         email=doc.get("email"),
#         role=doc["role"]
#     )

# @app.post("/auth/login", response_model=TokenResponse)
# def login(form_data: OAuth2PasswordRequestForm = Depends()):
#     """
#     Login: devuelve JWT. Form-data: username, password
#     """
#     user = authenticate_user(form_data.username, form_data.password)
#     if not user:
#         raise HTTPException(status_code=400, detail="Usuario o contraseña inválidos")
#     token = create_access_token({"sub": user["username"], "role": user["role"]})
#     return TokenResponse(access_token=token)

# # ---------------------------
# # User endpoints
# # ---------------------------
# @app.get("/users/me", response_model=UserOut)
# def me(current_user=Depends(get_current_user)):
#     return UserOut(id=current_user["_id"], username=current_user["username"],
#                    email=current_user.get("email"), role=current_user["role"])

# @app.post("/users/upgrade", response_model=UserOut)
# def upgrade_role(req: RoleChangeRequest, current_user=Depends(get_current_user)):
#     """
#     Permite al usuario actualizar su rol a 'chef' o 'proveedor'.
#     Si en el futuro quieres que admin apruebe, cambia la lógica para
#     crear un documento 'pending' en recipes/profiles.
#     """
#     new_role = req.new_role.lower()
#     if new_role not in ("chef", "proveedor"):
#         raise HTTPException(400, "Rol inválido. Solo 'chef' o 'proveedor'")

#     # Actualiza en DB
#     users_col.update_one({"_id": current_user["_id"]}, {"$set": {"role": new_role}})
#     updated = get_user_by_username(current_user["username"])
#     return UserOut(id=updated["_id"], username=updated["username"],
#                    email=updated.get("email"), role=updated["role"])

# # ---------------------------
# # Simple recipes & providers endpoints (base)
# # ---------------------------
# class RecipeCreate(BaseModel):
#     title: str
#     ingredients: list[str]
#     steps: list[str]
#     chef_username: Optional[str] = None

# @app.post("/recipes")
# def create_recipe(recipe: RecipeCreate, current_user=Depends(get_current_user)):
#     # Only chefs (or admins) can upload recipes on web — enforce if needed:
#     if current_user["role"] not in ("chef", "admin"):
#         raise HTTPException(403, "Solo chefs (o admin) pueden subir recetas")
#     doc = {
#         "_id": f"{recipe.title}-{datetime.utcnow().timestamp()}",
#         "title": recipe.title,
#         "ingredients": recipe.ingredients,
#         "steps": recipe.steps,
#         "chef": recipe.chef_username or current_user["username"],
#         "approved": False,  # pendiente de aprobación por admin
#         "created_at": datetime.utcnow().isoformat()
#     }
#     recipes_col.insert_one(doc)
#     return {"status": "ok", "recipe_id": doc["_id"], "approved": doc["approved"]}

# @app.get("/recipes")
# def list_recipes(q: Optional[str] = None):
#     query = {}
#     if q:
#         # búsqueda simple por título o ingrediente
#         query["$or"] = [
#             {"title": {"$regex": q, "$options": "i"}},
#             {"ingredients": {"$regex": q, "$options": "i"}}
#         ]
#     docs = list(recipes_col.find(query, {"_id": 1, "title": 1, "chef": 1, "approved": 1}))
#     return docs

# # Providers endpoints
# class ProviderCreate(BaseModel):
#     name: str
#     contact: str
#     products: list[str]
#     location: Optional[str] = None

# @app.post("/providers")
# def create_provider(provider: ProviderCreate, current_user=Depends(get_current_user)):
#     # Solo usuarios con rol 'proveedor' pueden crear su ficha
#     if current_user["role"] != "proveedor":
#         raise HTTPException(403, "Solo usuarios con rol 'proveedor' pueden crear proveedor")
#     doc = {
#         "_id": f"prov-{provider.name}-{datetime.utcnow().timestamp()}",
#         "name": provider.name,
#         "contact": provider.contact,
#         "products": provider.products,
#         "location": provider.location,
#         "owner": current_user["_id"],
#         "created_at": datetime.utcnow().isoformat()
#     }
#     providers_col.insert_one(doc)
#     return {"status": "ok", "provider_id": doc["_id"]}

# @app.get("/providers")
# def list_providers():
#     docs = list(providers_col.find({}, {"_id": 1, "name": 1, "products": 1, "contact": 1}))
#     return docs

# # ---------------------------
# # Startup / Shutdown
# # ---------------------------
# @app.on_event("startup")
# def startup():
#     # create indexes simple (opcional)
#     users_col.create_index("username", unique=True)
#     print("✅ API arrancada. Conexión a Mongo OK.")

# @app.on_event("shutdown")
# def shutdown():
#     client.close()
#     print("🔴 Conexión Mongo cerrada.")


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

load_dotenv()

# ---------------------------
# Config
# ---------------------------
SECRET_KEY = os.getenv("JWT_SECRET", "cambiame_por_una_clave_segura_en_prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 días

MONGO_CONN = os.getenv("MONGO_URL") or os.getenv("MONGO_PUBLIC_URL")
if not MONGO_CONN:
    raise RuntimeError("No se encontró MONGO_URL ni MONGO_PUBLIC_URL en variables de entorno")

DB_NAME = os.getenv("DB_NAME", "camcook")

# ---------------------------
# MongoDB
# ---------------------------
client = MongoClient(MONGO_CONN)
db = client[DB_NAME]  # explicitamente seleccionamos la DB

users_col = db["users"]
recipes_col = db["recipes"]
providers_col = db["providers"]

# ---------------------------
# Security utilities
# ---------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def hash_password(password: str) -> str:
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
# FastAPI app
# ---------------------------
app = FastAPI(title="Cam Cook - API (FastAPI + MongoDB)")

# Aquí puedes copiar el resto de tu código: CRUD de usuarios, login, recetas, proveedores...
# Endpoint raíz simple para probar la API
@app.get("/")
def root():
    return {"message": "API CamCook funcionando ✅"}
