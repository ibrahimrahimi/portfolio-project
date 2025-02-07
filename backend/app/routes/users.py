from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import User
from app.auth import hash_password
from pydantic import BaseModel, EmailStr

router = APIRouter(prefix="/users", tags=["Users"])


# Database session dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# User Registration Schema
class UserCreate(BaseModel):
    email: EmailStr
    password: str


# Register New User
@router.post("/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    """Register a new user with hashed password."""
    
    # Check if the email already exists
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash the password before storing
    hashed_password = hash_password(user.password)

    # Create new user
    new_user = User(email=user.email, password=hash_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message":"User registered successfully"}

