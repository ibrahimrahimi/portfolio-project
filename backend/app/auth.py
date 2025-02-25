from passlib.context import CryptContext
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
import os
from dotenv import load_dotenv

# Load evironment variables
load_dotenv()

# Secret key for JWT
SECRET_KEY = os.getenv("SECRET_KEY", "thisismysecrectkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2PasswordBearer tells FastAPI we expect an "Authorization: Bearer <token> header"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def hash_password(password: str) -> str:
    """Hash a password securely."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify if a given password matches the stored hash."""
    return pwd_context.verify(plain_password, hashed_password)

def create_tokens(data: dict, expires_delta: timedelta = None):
    """Generate both access and refresh tokens."""

    # Short-lived access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = jwt.encode(
        {**data, "exp": datetime.utcnow() + access_token_expires},
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    # Longer-lived refresh token
    refresh_access_expires = timedelta(days=5)
    refresh_token = jwt.encode(
        {**data, "exp": datetime.utcnow() + refresh_access_expires},
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return {"access_token": access_token,  "refresh_token": refresh_token}

def get_current_user(token: str = Depends(oauth2_scheme)):
    """Extract and validate the user from JWT token."""
    try:
        # Decode JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        role = payload.get("role")

        if email is None or role is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {"email": email, "role": role}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def require_role(required_role: str):  
    """Dependency to enforce role-based access control."""
    def role_dependency(user: dict = Depends(get_current_user)):
        
        # Ensure case-insensitive and space-free comparison
        if user.get('role').strip().lower() != required_role.strip().lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Requires '{required_role}' role."
            )
        
        return user
    return role_dependency
