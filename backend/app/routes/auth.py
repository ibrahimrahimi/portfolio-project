from fastapi import APIRouter, Depends, HTTPException
from authlib.integrations.starlette_client import OAuth
from starlette.requests import Request
import os
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import User
from app.auth import create_access_token

# Load environment variables
load_dotenv()

# Initialize OAuth
oauth = OAuth()

oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    access_token_url="https://oauth2.googleapis.com/token",
    client_kwargs={
        "scope": "openid email profile",
        "response_type": "code",
        "prompt": "consent"
    },
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration"
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Database session dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Google OAuth2 Login URL
@router.get("/login/google")
async def login_google(request: Request):
    """Redirect users to Google Login."""
    return await oauth.google.authorize_redirect(request, os.getenv("GOOGLE_REDIRECT_URI"))

@router.get("/callback")
async def auth_callback(request: Request, db: Session = Depends(get_db)):
    """Handle OAuth2 callback and authenticate user."""
    
    # Get token response from Google
    token = await oauth.google.authorize_access_token(request)

    # Extract `id_token` manually
    id_token = token.get("id_token")
    if not id_token:
        raise HTTPException(status_code=400, detail="Missing id_token in response")

    # Extract user info from `userinfo` (instead of parsing id_token separately)
    user_info = token.get("userinfo")

    if not user_info:
        raise HTTPException(status_code=400, detail="Failed to get user info")

    # Check if user exists in the database
    db_user = db.query(User).filter(User.email == user_info["email"]).first()

    if not db_user:
        db_user = User(email=user_info["email"], password="oauth")
        db.add(db_user)
        db.commit()
        db.refresh(db_user)

    # Generate JWT token
    access_token = create_access_token(data={"sub": db_user.email})

    return {"access_token": access_token, "token_type": "bearer"}
