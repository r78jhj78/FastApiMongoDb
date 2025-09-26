from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "postgresql://cookcambd_user:HOM6Vqk6KneG5hCdBSYPSybYo1BBaf5W@dpg-d3aafkidbo4c738ls860-a.oregon-postgres.render.com/cookcambd"

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
