from fastapi import APIRouter, Depends
from app.auth import get_current_user

router = APIRouter(prefix="/protected", tags=["Protected Routes"])


@router.get("/dashboard")
async def protected_dashboard(current_user: str = Depends(get_current_user)):
    """Only authenticated users can access this"""
    return {"message": "Welcome to your dashboard", "user": current_user}


@router.get("/profile")
async def user_profile(current_user: str = Depends(get_current_user)):
    """User profile, accessible only by logged-in users"""
    return {"email":current_user, "message":"This is your profile!"}