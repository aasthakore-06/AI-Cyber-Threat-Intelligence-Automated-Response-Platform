from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import UserModel
from app.core.security import verify_password, create_access_token, get_current_admin

router = APIRouter(tags=["Auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/auth/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.username == body.username).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Wrong username or password")
    return {"access_token": create_access_token(user.username), "token_type": "bearer", "username": user.username}


@router.get("/auth/me")
def me(user: str = Depends(get_current_admin)):
    return {"username": user, "role": "admin"}
