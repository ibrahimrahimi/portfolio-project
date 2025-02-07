from fastapi import FastAPI
from app.routes import blogs, users

app = FastAPI(title="Portfolio API")

# Include API routes
app.include_router(blogs.router)
app.include_router(users.router)

@app.get("/")
def root():
    return {"Message": "Welcome to My Portfolio API"}