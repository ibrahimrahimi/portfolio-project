from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
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
