from dotenv import load_dotenv
import os
from pymongo import MongoClient

# Carga variables desde el .env
load_dotenv()

# Lee las variables
MONGO_URL = os.getenv("MONGO_URL")
JWT_SECRET = os.getenv("JWT_SECRET")

print("MONGO_URL:", MONGO_URL)
print("JWT_SECRET:", JWT_SECRET)

# Conexión de prueba a MongoDB
client = MongoClient(MONGO_URL)
db = client.get_database()  # usa la DB de la URL
print("✅ Conexión a Mongo OK. Collections existentes:", db.list_collection_names())
