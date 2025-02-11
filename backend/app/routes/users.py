from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from datetime import timedelta
from app.database import SessionLocal
from app.models import User
from app.auth import hash_password, verify_password, create_tokens

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

# Login Schema
class UserLogin(BaseModel):
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
    new_user = User(email=user.email, password=hashed_password, role="user")
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message":"User registered successfully"}


# Login Route
@router.post("/login")
def login_user(user: UserLogin, db: Session = Depends(get_db)):
    """Authenticate user and return JWT token."""

    # Find user by email
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=400, detail="Invalid credentials!")
    
    # Generate JWT token
    tokens = create_tokens(data={"sub": db_user.email}, expires_delta=timedelta(minutes=30))

    return tokens
