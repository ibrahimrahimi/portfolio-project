from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from app.routes import blogs, users, auth
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = FastAPI(title="Portfolio API")

# Ensure secret key is set correctly
SECRET_KEY = os.getenv("SESSION_SECRET_KEY", "thisismysecrectkey")

# Add session middleware for OAuth authentication
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, session_cookie="oauth_session")

# Include API routes
app.include_router(blogs.router)
app.include_router(users.router)
app.include_router(auth.router)

@app.get("/")
def root():
    return {"Message": "Welcome to My Portfolio API"}
