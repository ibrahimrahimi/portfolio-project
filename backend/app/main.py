from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from app.routes import blogs, users, auth
import os

app = FastAPI(title="Portfolio API")

# Add Session Middlewar (Required for OAuth2)
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET_KEY", "thisismysecrectkey"))

# Include API routes
app.include_router(blogs.router)
app.include_router(users.router)
app.include_router(auth.router)

@app.get("/")
def root():
    return {"Message": "Welcome to My Portfolio API"}