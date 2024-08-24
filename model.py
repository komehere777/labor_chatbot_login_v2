from pymongo import MongoClient
from config import MONGO_URI, MONGO_DBNAME
from datetime import datetime
import pytz
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId

def get_mongo_client():
  uri = MONGO_URI
  db_name = MONGO_DBNAME
  client = MongoClient(uri)
  db = client[db_name]

  return db

def get_all_contents():
  db = get_mongo_client()
  collection = db['team3']
  
  documents = collection.find({}, {"_id": 0, "content": 1})

  return [doc['content'] for doc in documents]

# 세션에 chat_history가 있으면 update, 없으면 insert로 처리하면 되는게 아닐까?
# 그럼 같은 주제의 history라는걸 구분하기 위해서는?
# history_id를 넣어야하나?
# 아니면 임시파일에 밀어넣고 한번에 업로드?

def save_data_to_db(user_id, user, ai):
  db = get_mongo_client()
  collection = db['team3']
  document = {"user_id":user_id, "chat": []}

  collection.insert_one({"user_id":user_id, "user": user, "ai": ai, "datetime":datetime.now(pytz.timezone('Asia/Seoul'))})

def get_user_chat_historys(username):
  db = get_mongo_client()
  collection = db['chat_history']

  history = collection.find({"username": username},{"history_id":1, "chat":1, "_id": 0})
  chat_history = []
  for doc in history:
    chat_history.append({
      'history_id': doc.get('history_id'),
      'chat': doc.get('chat', [])
    })
  return chat_history

def get_user_chat(history_id):
  db = get_mongo_client()
  collection = db['chat_history']

  history_id = int(history_id)
  chat = collection.find_one({"history_id": history_id}, {"chat":1, "_id": 0})
  return chat.get('chat', [])

class User(UserMixin):
    def __init__(self, user_id, username, email, password_hash):
        self.id = user_id
        self.username = username
        self.email = email
        self.password_hash = password_hash

    @staticmethod
    def get(user_id):
        db = get_mongo_client()
        user_data = db.users.find_one({"_id": ObjectId(user_id)})
        if not user_data:
            return None
        return User(str(user_data["_id"]), user_data["username"], user_data["email"], user_data["password_hash"])

    @staticmethod
    def get_by_email(email):
        db = get_mongo_client()
        user_data = db.users.find_one({"email": email})
        if not user_data:
            return None
        return User(
            user_id=user_data['_id'],
            username=user_data['username'],
            email=user_data['email'],
            password_hash=user_data['password_hash']
        )

def create_user(username, email, password):
    db = get_mongo_client()
    existing_user = db.users.find_one({"email": email}) or db.users.find_one({"username": username})
    if existing_user:
        return False
    hashed_password = generate_password_hash(password)
    user_id = db.users.insert_one({
        "username": username,
        "email": email,
        "password_hash": hashed_password
    }).inserted_id
    return User.get(user_id)

def authenticate_user(email, password):
    user = User.get_by_email(email)
    if user and check_password_hash(user.password_hash, password):
        print(f"Authenticated user: {user}")  # 디버그 출력
        return user
    return None