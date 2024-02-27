rom fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import IntegrityError
from jose import jwt, JWTError
from cachetools import TTLCache
from typing import Dict, Optional

# Initialize FastAPI app
app = FastAPI()

# Configure SQLAlchemy
database_url = "mysql+mysqlconnector://<db_username>:<db_password>@<db_host>:<db_port>/<db_name>"
engine = create_engine(database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Configure JWT secret key
secret_key = "your-secret-key"
algorithm = "HS256"

# Configure in-memory cache
cache = TTLCache(maxsize=1000, ttl=300)

# Define SQLAlchemy models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True)
    password = Column(String(255))

class Post(Base):
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True, index=True)
    text = Column(String(500))
    user_id = Column(Integer, ForeignKey("users.id"))


# Pydantic schemas
class UserCreate(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class PostCreate(BaseModel):
    text: str


# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Authentication dependencies and utility functions
def create_access_token(user_id: int) -> str:
    """Create JWT access token with user ID payload."""
    payload = {"user_id": user_id}
    return jwt.encode(payload, secret_key, algorithm=algorithm)

def decode_access_token(token: str) -> Optional[Dict]:
    """Decode and verify JWT access token, returning payload if valid."""
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        return payload
    except JWTError:
        return None

def authenticate_user(email: str, password: str, db) -> Optional[int]:
    """Authenticate user by email and password, returning user ID if valid."""
    user = db.query(User).filter(User.email == email, User.password == password).first()
    if user:
        return user.id

    return None

def get_current_user(token: str = Depends(decode_access_token)) -> Optional[int]:
    """Get current authenticated user ID from access token."""
    if token:
        return token.get("user_id")

    return None

def is_authenticated(user_id: int = Depends(get_current_user)) -> bool:
    """Check if user is authenticated."""
    return user_id is not None

def get_cached_data(key: str) -> Optional[Dict]:
    """Get data from cache."""
    return cache.get(key)

def cache_data(key: str, data: Dict):
    """Cache data for 5 minutes."""
    cache[key] = data


# Endpoint to sign up a new user
@app.post("/signup")
async def signup(user: UserCreate, db = Depends(get_db)):
    try:
        new_user = User(email=user.email, password=user.password)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        access_token = create_access_token(new_user.id)
        return {"access_token": access_token}
    except IntegrityError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")


# Endpoint to login an existing user
@app.post("/login")
async def login(user: UserLogin, db = Depends(get_db)):
    user_id = authenticate_user(user.email, user.password, db)
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    
    access_token = create_access_token(user_id)
    return {"access_token": access_token}


# Endpoint to add a new post
@app.post("/addPost")
async def add_post(post: PostCreate, is_auth: bool = Depends(is_authenticated), db = Depends(get_db)):
    if not is_auth:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    # Validate payload size
    if len(post.text.encode()) > 1048576:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Payload too large")

    # Get current user ID
    current_user = is_auth

    # Save post in database
    new_post = Post(text=post.text, user_id=current_user)
    db.add(new_post)
    db.commit()
    db.refresh(new_post)

    return {"post_id": new_post.id}


# Endpoint to get all posts by the current user
@app.get("/getPosts")
async def get_posts(is_auth: bool = Depends(is_authenticated), db = Depends(get_db)):
    if not is_auth:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    current_user = is_auth

    # Check cache for cached data
    cached_posts = get_cached_data(f"posts_{current_user}")
    if cached_posts:
        return cached_posts

    # Get posts from database
    posts = db.query(Post).filter(Post.user_id == current_user).all()

    # Cache posts for 5 minutes
    cache_data(f"posts_{current_user}", {"posts": [post.text for post in posts]})

    return {"posts": [post.text for post in posts]}


# Endpoint to delete a post by post ID
@app.delete("/deletePost/{post_id}")
async def delete_post(post_id: int, is_auth: bool = Depends(is_authenticated), db = Depends(get_db)):
    if not is_auth:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    current_user = is_auth

    # Check if post exists and belongs to the current user
    post = db.query(Post).filter(Post.id == post_id, Post.user_id == current_user).first()
    if not post:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

    # Delete post from database
    db.delete(post)
    db.commit()

    return {"message": "Post deleted"}


# Run the FastAPI app
if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)
    app.run()
