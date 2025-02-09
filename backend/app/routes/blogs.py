from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.auth import require_role
from app.database import SessionLocal
from app.models import Blog

router = APIRouter(prefix="/blogs", tags=["Blogs"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/")
def get_blogs(db: Session = Depends(get_db)):
    return db.query(Blog).all()


@router.delete("/blogs/{blog_id}")
async def delete_blog(blog_id: int, user: dict = Depends(require_role("admin"))):
    """Only admin users can delete blogs."""
    return {"message": f"Blog {blog_id} deleted by {user['email']}"}