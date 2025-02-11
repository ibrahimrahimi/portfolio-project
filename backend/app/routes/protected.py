from fastapi import APIRouter, Depends, HTTPException
from app.auth import get_current_user, require_role

router = APIRouter(prefix="/protected", tags=["Protected Routes"])

# Only admins can access this
@router.get("/dashboard")
async def admin_dashboard(user: dict = Depends(get_current_user)):
    """Allow only admin users to view the dashboard."""
    if user.get('role') and user.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Access denied: Admins only")
    return {"message": f"Welcome to the admin dashboard, {user['email']}!"}

# All authenticated users can access this
@router.get("/profile")
async def user_profile(user: str = Depends(get_current_user)):
    print('this is the profile route', user)
    """Allow any authenticated user to view their profile."""
    return {"email": user["email"], "role": user["role"]}
