from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware           # ← nouveau
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
# Utilise la nouvelle API declarative de SQLAlchemy 2.0
from sqlalchemy.orm import declarative_base, sessionmaker, Session
import bcrypt

# FastAPI app
app = FastAPI()

# 🔧 CORS middleware (à déclarer AVANT tes routes)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # ton front Next.js
    allow_credentials=True,
    allow_methods=["*"],       # GET, POST, OPTIONS…
    allow_headers=["*"],       # Content-Type, Authorization…
)

# SQLite DB setup
DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()  # ← import corrigé

# DB Session
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# User Model (SQLAlchemy)
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    firstname = Column(String)
    lastname = Column(String)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(String)
    department = Column(String, nullable=True)
    admin_code = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

# Pydantic Models
class UserSignup(BaseModel):
    firstname: str
    lastname: str
    email: EmailStr
    password: str
    role: str
    department: str | None = None
    adminCode: str | None = None

class UserSignin(BaseModel):
    email: EmailStr
    password: str

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Signup route
@app.post("/signup")
def signup(user: UserSignup, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pw = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    new_user = User(
        firstname=user.firstname,
        lastname=user.lastname,
        email=user.email,
        password=hashed_pw.decode('utf-8'),
        role=user.role,
        department=user.department,
        admin_code=user.adminCode,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully"}

# Signin route
@app.post("/signin")
def signin(user: UserSignin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not bcrypt.checkpw(user.password.encode('utf-8'), db_user.password.encode('utf-8')):
        raise HTTPException(status_code=400, detail="Invalid email or password")
    return {"message": f"Welcome {db_user.firstname}", "role": db_user.role}
