from fastapi import APIRouter, Depends, HTTPException
from app.auth import get_current_user, require_role
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import User

router = APIRouter(prefix="/protected", tags=["Protected Routes"])

# Database session dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Only admins can access this
@router.get("/dashboard")
async def admin_dashboard(user: dict = Depends(require_role("admin"))):
    """Allow only admin users to view the dashboard."""
    return {"message": f"Welcome to the admin dashboard, {user['email']}!"}

# All authenticated users can access this
@router.get("/profile/{email}")
async def user_profile(
    email: str,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Users can only view their own profile, but admins can view any profile"""

    # If the user is NOT an admin, they can ONLY view their own profile
    if user.get('role', '').lower() != 'admin' and user.get('email', '') != email:
        raise HTTPException(
            status_code=403,
            detail="Access denied: You can only view your own profile."
        )

    # Fetch user from the database
    db_user = db.query(User).filter(User.email == email).first()
    if not db_user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )
    return {"email": db_user.email, "role": db_user.role}
