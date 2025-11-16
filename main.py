from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime, timedelta
from pymongo import MongoClient
from bson import ObjectId
from passlib.context import CryptContext
from jose import JWTError, jwt
import os
import shutil
import random
import threading
import time

# ============================================================
#                      APP SETUP
# ============================================================
BACKEND_BASE_URL = os.getenv("BACKEND_BASE_URL", "http://127.0.0.1:8000")


app = FastAPI()

origins = [
    "http://localhost:3000",                       # local dev
    "https://sm-driving-frontend.onrender.com",   # your live frontend
]


# ============================================================
#                     MONGODB SETUP
# ============================================================

# If environment variable exists → use it (for deployment)
# If not → use local MongoDB
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")

client = MongoClient(MONGO_URI)
db = client["sm_driving_school"]

inquiry_collection = db["inquiries"]
service_collection = db["services"]
admin_collection = db["admins"]

# ============================================================
#                 PASSWORD / AUTH UTILITIES
# ============================================================
# ------------------ Password Utilities ------------------
# Simple version: store plain password (for small internal project)
def verify_password(plain: str, stored: str) -> bool:
    return plain == stored

def get_password_hash(password: str) -> str:
    return password


# ============================================================
#                    JWT SETTINGS
# ============================================================

SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_THIS_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ============================================================
#                     Pydantic Models
# ============================================================

class Inquiry(BaseModel):
    name: str
    email: str
    mobile: str
    message: str


class Service(BaseModel):
    serviceName: str
    documents: str
    price: str
    duration: str
    description: str
    imageURL: str = ""


class AdminCreate(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ============================================================
#                   Inquiry Routes
# ============================================================

@app.post("/inquiry")
def create_inquiry(inquiry: Inquiry):
    data = inquiry.dict()
    data["date"] = datetime.utcnow()
    inquiry_collection.insert_one(data)
    return {"message": "Your inquiry has been submitted successfully!"}


@app.get("/inquiries")
def get_inquiries():
    data = []
    for doc in inquiry_collection.find():
        doc["_id"] = str(doc["_id"])
        data.append(doc)
    return data


@app.delete("/inquiry/{id}")
def delete_inquiry(id: str):
    try:
        result = inquiry_collection.delete_one({"_id": ObjectId(id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid ID format")

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Inquiry not found")

    return {"message": "Inquiry deleted successfully"}


# ============================================================
#                      Service Routes
# ============================================================

@app.post("/service")
def create_service(service: Service):
    data = service.dict()
    data["date"] = datetime.utcnow()
    result = service_collection.insert_one(data)
    data["_id"] = str(result.inserted_id)
    return data


@app.get("/services")
def get_services():
    data = []
    for doc in service_collection.find():
        doc["_id"] = str(doc["_id"])
        data.append(doc)
    return data


@app.delete("/service/{id}")
def delete_service(id: str):
    try:
        result = service_collection.delete_one({"_id": ObjectId(id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid ID format")

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Service not found")

    return {"message": "Service deleted successfully"}


# ============================================================
#       Image Upload – Slider Images
# ============================================================

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post("/upload-image")
async def upload_image(file: UploadFile = File(...)):
    file_path = os.path.join(UPLOAD_DIR, file.filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {"image_url": f"{BACKEND_BASE_URL}/uploads/{file.filename}"}



@app.get("/images")
def list_images():
    files = os.listdir(UPLOAD_DIR)
    urls = [f"{BACKEND_BASE_URL}/uploads/{f}" for f in files]
    return {"images": urls}



@app.delete("/delete-image/{filename}")
def delete_image(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Image not found")

    os.remove(file_path)
    return {"message": "Image deleted successfully"}


app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# ============================================================
#       Image Upload – Service Images
# ============================================================

SERVICE_UPLOAD_DIR = "service_uploads"
os.makedirs(SERVICE_UPLOAD_DIR, exist_ok=True)


@app.post("/upload-service-image")
async def upload_service_image(file: UploadFile = File(...)):
    file_path = os.path.join(SERVICE_UPLOAD_DIR, file.filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {"image_url": f"{BACKEND_BASE_URL}/service-uploads/{file.filename}"}



app.mount("/service-uploads", StaticFiles(directory=SERVICE_UPLOAD_DIR), name="service_uploads")


# ============================================================
#                    Admin Routes
# ============================================================

@app.get("/check-admin")
def check_admin():
    count = admin_collection.count_documents({})
    return {"exists": count > 0}


@app.post("/register-admin")
def register_admin(admin: AdminCreate):
    if admin_collection.find_one({"username": admin.username}):
        raise HTTPException(status_code=400, detail="Admin already exists")

    hashed_pw = get_password_hash(admin.password)
    admin_collection.insert_one({"username": admin.username, "password": hashed_pw})

    return {"message": "Admin registered successfully!"}


@app.post("/login", response_model=TokenResponse)
def login(data: LoginRequest):
    admin = admin_collection.find_one({"username": data.username})
    if not admin or not verify_password(data.password, admin["password"]):
        raise HTTPException(status_code=400, detail="Invalid username or password")

    token = create_access_token({"sub": admin["username"]})
    return {"access_token": token, "token_type": "bearer"}


# ============================================================
#                  OTP Login
# ============================================================

OTP_VALIDITY_MINUTES = 5


@app.post("/request-otp")
def request_otp(data: dict):
    username = data.get("username")
    admin = admin_collection.find_one({"username": username})

    if not admin:
        raise HTTPException(status_code=400, detail="Invalid username")

    otp = str(random.randint(100000, 999999))
    expiry = datetime.utcnow() + timedelta(minutes=OTP_VALIDITY_MINUTES)

    admin_collection.update_one(
        {"username": username},
        {"$set": {"otp": otp, "otp_expiry": expiry}},
    )

    return {"message": "OTP generated", "otp": otp}  # remove OTP in production


@app.post("/login-otp", response_model=TokenResponse)
def login_otp(data: dict):
    username = data.get("username")
    otp = data.get("otp")

    admin = admin_collection.find_one({"username": username})

    if not admin or "otp" not in admin:
        raise HTTPException(status_code=400, detail="No OTP requested")

    if datetime.utcnow() > admin["otp_expiry"]:
        raise HTTPException(status_code=400, detail="OTP expired")

    if otp != admin["otp"]:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    admin_collection.update_one(
        {"username": username},
        {"$unset": {"otp": "", "otp_expiry": ""}},
    )

    token = create_access_token({"sub": username})
    return {"access_token": token, "token_type": "bearer"}


# ============================================================
#            OTP Cleanup Background Thread
# ============================================================

def cleanup_expired_otps():
    while True:
        now = datetime.utcnow()
        admin_collection.update_many(
            {"otp_expiry": {"$lte": now}},
            {"$unset": {"otp": "", "otp_expiry": ""}},
        )
        time.sleep(60)


@app.on_event("startup")
def start_cleanup_thread():
    threading.Thread(target=cleanup_expired_otps, daemon=True).start()
