from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Table
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
import bcrypt
from typing import Optional, List

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Association table
user_formation_table = Table(
    'user_formation',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('formation_id', Integer, ForeignKey('formations.id'))
)

# Models
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

    formations = relationship("Formation", secondary=user_formation_table, back_populates="users")

class Formation(Base):
    __tablename__ = "formations"
    id = Column(Integer, primary_key=True, index=True)
    titre = Column(String)
    description = Column(String)
    department = Column(String)

    users = relationship("User", secondary=user_formation_table, back_populates="formations")

Base.metadata.create_all(bind=engine)

# Pydantic models
class UserSignup(BaseModel):
    firstname: str
    lastname: str
    email: EmailStr
    password: str
    role: str
    department: Optional[str] = None
    adminCode: Optional[str] = None

class UserSignin(BaseModel):
    email: EmailStr
    password: str

class UserUpdate(BaseModel):
    firstname: Optional[str] = None
    lastname: Optional[str] = None
    email: Optional[EmailStr] = None
    department: Optional[str] = None
    role: Optional[str] = None

class UserOut(BaseModel):
    id: int
    firstname: str
    lastname: str
    email: EmailStr
    role: str
    department: Optional[str]

    class Config:
        orm_mode = True

class FormationCreate(BaseModel):
    titre: str
    description: str
    department: str

class FormationOut(BaseModel):
    id: int
    titre: str
    description: str
    department: str

    class Config:
        orm_mode = True

class InscriptionRequest(BaseModel):
    user_id: int
    formation_id: int

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Routes ---------------------

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

@app.post("/signin")
def signin(user: UserSignin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not bcrypt.checkpw(user.password.encode('utf-8'), db_user.password.encode('utf-8')):
        raise HTTPException(status_code=400, detail="Invalid email or password")

    return {
        "message": f"Bienvenue {db_user.firstname}",
        "id": db_user.id,
        "firstname": db_user.firstname,
        "lastname": db_user.lastname,
        "email": db_user.email,
        "role": db_user.role,
        "department": db_user.department
    }

@app.put("/update_profile/{user_id}")
def update_profile(user_id: int, user_update: UserUpdate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    if user_update.firstname:
        db_user.firstname = user_update.firstname
    if user_update.lastname:
        db_user.lastname = user_update.lastname
    if user_update.email:
        db_user.email = user_update.email
    if user_update.department:
        db_user.department = user_update.department
    if user_update.role:
        db_user.role = user_update.role

    db.commit()
    db.refresh(db_user)
    return {"message": "Profile updated successfully", "user": db_user}

@app.delete("/delete_user/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(db_user)
    db.commit()
    return {"message": "User deleted successfully"}

@app.get("/users", response_model=List[UserOut])
def get_users(db: Session = Depends(get_db)):
    return db.query(User).all()

@app.get("/formations", response_model=List[FormationOut])
def get_formations(department: Optional[str] = None, db: Session = Depends(get_db)):
    if department:
        return db.query(Formation).filter(Formation.department == department).all()
    return db.query(Formation).all()

@app.post("/formations")
def create_formation(formation: FormationCreate, db: Session = Depends(get_db)):
    new_formation = Formation(**formation.dict())
    db.add(new_formation)
    db.commit()
    db.refresh(new_formation)
    return {"message": "Formation créée", "id": new_formation.id}

@app.put("/formations/{formation_id}")
def update_formation(formation_id: int, formation: FormationCreate, db: Session = Depends(get_db)):
    existing = db.query(Formation).filter(Formation.id == formation_id).first()
    if not existing:
        raise HTTPException(status_code=404, detail="Formation not found")
    
    existing.titre = formation.titre
    existing.description = formation.description
    existing.department = formation.department

    db.commit()
    db.refresh(existing)
    return {"message": "Formation updated successfully"}

@app.delete("/formations/{formation_id}")
def delete_formation(formation_id: int, db: Session = Depends(get_db)):
    formation = db.query(Formation).filter(Formation.id == formation_id).first()
    if not formation:
        raise HTTPException(status_code=404, detail="Formation not found")

    db.delete(formation)
    db.commit()
    return {"message": "Formation deleted successfully"}

@app.post("/inscription")
def inscrire_formation(data: InscriptionRequest, db: Session = Depends(get_db)):
    print("🔍 user_id:", data.user_id, "formation_id:", data.formation_id)

    user = db.query(User).filter(User.id == data.user_id).first()
    formation = db.query(Formation).filter(Formation.id == data.formation_id).first()

    if not user:
        print("❌ User not found")
    if not formation:
        print("❌ Formation not found")

    if not user or not formation:
        raise HTTPException(status_code=404, detail="Utilisateur ou formation introuvable")

    if formation in user.formations:
        raise HTTPException(status_code=400, detail="Déjà inscrit à cette formation")

    user.formations.append(formation)
    db.commit()
    return {"message": "Inscription réussie"}

@app.get("/mes_formations/{user_id}", response_model=List[FormationOut])
def mes_formations(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    return user.formations
