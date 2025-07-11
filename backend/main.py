from fastapi import FastAPI, HTTPException, Depends, status, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, DateTime, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.sql import func
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from typing import List, Optional
import os
import json

# --- 1. 設定 ---
# 環境変数から取得。OnRenderデプロイ時に設定
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://user:password@localhost/dbname")
SECRET_KEY = os.environ.get("SECRET_KEY", "your-super-secret-key") # 本番環境では強力なキーに変更

# --- 2. データベース設定 ---
Engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=Engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- 3. モデル定義 ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    user_identifier = Column(String, unique=True, index=True, length=7) # SHA-256ハッシュの最初の7文字

    friends_a = relationship("Friendship", foreign_keys="Friendship.user_id", back_populates="user_a")
    friends_b = relationship("Friendship", foreign_keys="Friendship.friend_id", back_populates="user_b")
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender")
    received_messages = relationship("Message", foreign_keys="Message.receiver_id", back_populates="receiver")

class Friendship(Base):
    __tablename__ = "friendships"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    friend_id = Column(Integer, ForeignKey("users.id"))
    status = Column(String, default="accepted") # シンプル化のため即時承認

    user_a = relationship("User", foreign_keys=[user_id])
    user_b = relationship("User", foreign_keys=[friend_id])

    __table_args__ = (UniqueConstraint('user_id', 'friend_id', name='_user_friend_uc'),)


class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    receiver_id = Column(Integer, ForeignKey("users.id"))
    content = Column(Text)
    timestamp = Column(DateTime, default=func.now())

    sender = relationship("User", foreign_keys=[sender_id])
    receiver = relationship("User", foreign_keys=[receiver_id])

# --- 4. スキーマ定義 ---
class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    user_identifier: str

    class Config:
        from_attributes = True

class FriendRequest(BaseModel):
    friend_identifier: str

class MessageCreate(BaseModel):
    receiver_identifier: str
    content: str

class MessageResponse(BaseModel):
    sender_id: int
    receiver_id: int
    content: str
    timestamp: str

    class Config:
        from_attributes = True

# --- 5. 認証設定 ---
pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_password_hash(password):
    full_hash = pwd_context.hash(password)
    return full_hash, full_hash[:7] # SHA-256ハッシュの最初の7文字

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

async def get_current_user_simple(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # 注意: ここではOAuth2PasswordRequestFormを直接使って簡易的な認証を行っています。
    # 本来はJWTトークンなどを検証し、ユーザー情報を取得します。
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

# --- 6. FastAPIアプリケーションインスタンス ---
app = FastAPI()

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=Engine)

# WebSocket接続を管理する辞書 {user_id: WebSocket}
active_connections: dict[int, WebSocket] = {}

# --- 7. APIエンドポイント ---

@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password, user_identifier = get_password_hash(user.password)

    existing_id_user = db.query(User).filter(User.user_identifier == user_identifier).first()
    if existing_id_user:
        raise HTTPException(status_code=400, detail="Generated user ID already exists. Please try another password.")

    new_user = User(username=user.username, hashed_password=hashed_password, user_identifier=user_identifier)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # 簡易的なログイン成功。実際にはJWTトークンを返す
    return {"message": "Login successful", "user_id": user.id, "username": user.username, "user_identifier": user.user_identifier}

@app.get("/users/search/{user_identifier}", response_model=UserResponse)
def search_user_by_id(user_identifier: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user_simple)):
    user = db.query(User).filter(User.user_identifier == user_identifier).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.post("/friends/add", status_code=status.HTTP_201_CREATED)
def add_friend(
    friend_req: FriendRequest,
    current_user: User = Depends(get_current_user_simple),
    db: Session = Depends(get_db)
):
    target_user = db.query(User).filter(User.user_identifier == friend_req.friend_identifier).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="Friend not found with this identifier")
    if target_user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot add yourself as a friend")

    # user_idとfriend_idの順序を正規化して、重複する友情関係を作成しないようにする
    u1, u2 = sorted([current_user.id, target_user.id])

    existing_friendship = db.query(Friendship).filter(
        (Friendship.user_id == u1) & (Friendship.friend_id == u2)
    ).first()

    if existing_friendship:
        raise HTTPException(status_code=400, detail="Already friends or pending request")

    new_friendship = Friendship(user_id=u1, friend_id=u2, status="accepted") # シンプル化のため即時承認
    db.add(new_friendship)
    db.commit()
    db.refresh(new_friendship)
    return {"message": "Friend added successfully"}

@app.get("/friends", response_model=List[UserResponse])
def get_friends(current_user: User = Depends(get_current_user_simple), db: Session = Depends(get_db)):
    friendships = db.query(Friendship).filter(
        ((Friendship.user_id == current_user.id) | (Friendship.friend_id == current_user.id))
    ).filter(Friendship.status == "accepted").all()

    friends = []
    for fs in friendships:
        if fs.user_id == current_user.id:
            friend = db.query(User).filter(User.id == fs.friend_id).first()
        else:
            friend = db.query(User).filter(User.id == fs.user_id).first()
        if friend:
            friends.append(friend)
    return friends

@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int, db: Session = Depends(get_db)):
    # 簡易的な認証 (実際はトークン検証などが必要)
    user_exists = db.query(User).filter(User.id == user_id).first()
    if not user_exists:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    active_connections[user_id] = websocket
    print(f"WebSocket connected: {user_id}")

    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            receiver_identifier = message_data.get("receiver_identifier")
            content = message_data.get("content")

            if not receiver_identifier or not content:
                continue

            receiver_user = db.query(User).filter(User.user_identifier == receiver_identifier).first()
            if not receiver_user:
                # 送信者側にエラーを返すなど
                continue

            new_message = Message(
                sender_id=user_id,
                receiver_id=receiver_user.id,
                content=content
            )
            db.add(new_message)
            db.commit()
            db.refresh(new_message)

            message_payload = {
                "type": "message",
                "sender_id": user_id,
                "receiver_id": receiver_user.id,
                "content": content,
                "timestamp": str(new_message.timestamp)
            }

            # 送信者へメッセージを送信 (オプショナル)
            # if user_id in active_connections:
            #     await active_connections[user_id].send_text(json.dumps(message_payload))

            # 受信者へメッセージを送信
            if receiver_user.id in active_connections:
                await active_connections[receiver_user.id].send_text(json.dumps(message_payload))

    except WebSocketDisconnect:
        if user_id in active_connections:
            del active_connections[user_id]
        print(f"WebSocket disconnected: {user_id}")
    except Exception as e:
        print(f"WebSocket error for user {user_id}: {e}")
        if user_id in active_connections:
            del active_connections[user_id]
