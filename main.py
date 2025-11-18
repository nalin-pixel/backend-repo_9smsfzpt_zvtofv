import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import bcrypt
import jwt
from bson import ObjectId

from database import db

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "60"))

app = FastAPI(title="Campus Internships & Placement API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

auth_scheme = HTTPBearer()


# ---------- Helpers ----------

def oid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def create_token(user: dict) -> str:
    payload = {
        "sub": str(user["_id"]),
        "role": user.get("role"),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRES_MIN),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def get_user_from_token(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = db["user"].find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user["_id"] = str(user["_id"])
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_role(role: str):
    def _checker(user = Depends(get_user_from_token)):
        if user.get("role") != role:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return _checker


# ---------- Models for Requests ----------

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str  # student | recruiter | admin
    roll: Optional[str] = None
    department: Optional[str] = None
    company: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    about: Optional[str] = None
    department: Optional[str] = None
    cgpa: Optional[float] = None
    skills: Optional[List[str]] = None
    resume_url: Optional[str] = None


class JobCreateRequest(BaseModel):
    title: str
    company: str
    description: str
    location: str
    stipend_min: Optional[int] = None
    stipend_max: Optional[int] = None
    department: Optional[str] = None
    required_skills: List[str] = []
    conversion_chance: Optional[str] = None
    deadline: Optional[str] = None


class StatusUpdateRequest(BaseModel):
    status: str  # shortlisted | selected | rejected
    note: Optional[str] = None


# ---------- Basic Routes ----------

@app.get("/")
def root():
    return {"message": "Internship & Placement API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# ---------- Auth ----------

@app.post("/auth/register")
def register(payload: RegisterRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    user_doc = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": hash_password(payload.password),
        "role": payload.role,
        "is_verified": True,
        "avatar_url": None,
        "roll": payload.roll,
        "department": payload.department,
        "cgpa": None,
        "skills": [],
        "resume_url": None,
        "phone": None,
        "about": None,
        "company": payload.company,
        "designation": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res_id = db["user"].insert_one(user_doc).inserted_id
    user_doc["_id"] = str(res_id)
    token = create_token(user_doc)
    return {"token": token, "user": {k: v for k, v in user_doc.items() if k != "password_hash"}}


@app.post("/auth/login")
def login(payload: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    user = db["user"].find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user_out = {k: v for k, v in user.items() if k != "password_hash"}
    user_out["_id"] = str(user_out["_id"])
    token = create_token(user)
    return {"token": token, "user": user_out}


@app.get("/me")
def me(user = Depends(get_user_from_token)):
    return user


# ---------- Student ----------

@app.put("/student/profile")
def update_student_profile(payload: UpdateProfileRequest, user = Depends(require_role("student"))):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    update["updated_at"] = datetime.now(timezone.utc)
    db["user"].update_one({"_id": ObjectId(user["_id"])}, {"$set": update})
    user_new = db["user"].find_one({"_id": ObjectId(user["_id"])})
    user_new["_id"] = str(user_new["_id"])
    user_new.pop("password_hash", None)
    return user_new


@app.post("/student/resume/upload")
def upload_resume(file: UploadFile = File(...), user = Depends(require_role("student"))):
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF allowed")
    uploads_dir = os.path.join(os.getcwd(), "uploads")
    os.makedirs(uploads_dir, exist_ok=True)
    filename = f"resume_{user['_id']}.pdf"
    file_path = os.path.join(uploads_dir, filename)
    with open(file_path, "wb") as f:
        f.write(file.file.read())
    public_url = f"/uploads/{filename}"
    if db is not None:
        db["user"].update_one({"_id": ObjectId(user["_id"])}, {"$set": {"resume_url": public_url}})
    return {"resume_url": public_url}


# Ensure uploads dir exists before mounting static files
uploads_dir_global = os.path.join(os.getcwd(), "uploads")
os.makedirs(uploads_dir_global, exist_ok=True)
from fastapi.staticfiles import StaticFiles
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")


# ---------- Jobs ----------

@app.post("/jobs")
def create_job(payload: JobCreateRequest, recruiter = Depends(require_role("recruiter"))):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    doc = payload.model_dump()
    doc.update({
        "recruiter_id": recruiter["_id"],
        "status": "open",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })
    _id = db["job"].insert_one(doc).inserted_id
    doc["_id"] = str(_id)
    return doc


@app.get("/jobs")
def list_jobs(q: Optional[str] = None, skill: Optional[str] = None, department: Optional[str] = None, only_open: bool = True, user = Depends(get_user_from_token)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    filt = {}
    if only_open:
        filt["status"] = "open"
    if department:
        filt["department"] = department
    if skill:
        filt["required_skills"] = {"$in": [skill]}
    if q:
        filt["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"company": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
        ]

    jobs = list(db["job"].find(filt).sort("created_at", -1))
    for j in jobs:
        j["_id"] = str(j["_id"])
        j["is_applied"] = False
    if user.get("role") == "student":
        app_docs = list(db["application"].find({"student_id": user["_id"]}))
        applied_job_ids = {a["job_id"] for a in app_docs}
        for j in jobs:
            j["is_applied"] = str(j["_id"]) in applied_job_ids
        skills_set = set(user.get("skills", []))
        jobs.sort(key=lambda x: -len(skills_set.intersection(set(x.get("required_skills", [])))))
    return jobs


@app.post("/jobs/{job_id}/apply")
def apply_job(job_id: str, user = Depends(require_role("student"))):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    job = db["job"].find_one({"_id": oid(job_id)})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    exists = db["application"].find_one({"job_id": job_id, "student_id": user["_id"]})
    if exists:
        raise HTTPException(status_code=400, detail="Already applied")
    app_doc = {
        "job_id": job_id,
        "student_id": user["_id"],
        "status": "applied",
        "note": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    _id = db["application"].insert_one(app_doc).inserted_id
    app_doc["_id"] = str(_id)
    # notify recruiter
    db["notification"].insert_one({
        "user_id": job.get("recruiter_id"),
        "message": f"New applicant for {job.get('title')}",
        "read": False,
        "type": "application",
        "created_at": datetime.now(timezone.utc),
    })
    return app_doc


@app.get("/student/applications")
def my_applications(user = Depends(require_role("student"))):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    apps = list(db["application"].find({"student_id": user["_id"]}).sort("created_at", -1))
    for a in apps:
        a["_id"] = str(a["_id"])
        job = db["job"].find_one({"_id": ObjectId(a["job_id"])})
        if job:
            job["_id"] = str(job["_id"])
        a["job"] = job
    return apps


# ---------- Recruiter ----------

@app.get("/recruiter/jobs")
def recruiter_jobs(recruiter = Depends(require_role("recruiter"))):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    jobs = list(db["job"].find({"recruiter_id": recruiter["_id"]}).sort("created_at", -1))
    for j in jobs:
        j["_id"] = str(j["_id"])
    return jobs


@app.get("/recruiter/jobs/{job_id}/applicants")
def job_applicants(job_id: str, recruiter = Depends(require_role("recruiter"))):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    job = db["job"].find_one({"_id": oid(job_id), "recruiter_id": recruiter["_id"]})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    apps = list(db["application"].find({"job_id": job_id}).sort("created_at", -1))
    for a in apps:
        a["_id"] = str(a["_id"])
        student = db["user"].find_one({"_id": ObjectId(a["student_id"])})
        if student:
            student["_id"] = str(student["_id"])
            student.pop("password_hash", None)
        a["student"] = student
    job_out = {**{k: v for k, v in job.items() if k != "_id"}, "_id": str(job["_id"]) }
    return {"job": job_out, "applications": apps}


@app.patch("/applications/{app_id}")
def update_application_status(app_id: str, payload: StatusUpdateRequest, recruiter = Depends(require_role("recruiter"))):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    app_doc = db["application"].find_one({"_id": oid(app_id)})
    if not app_doc:
        raise HTTPException(status_code=404, detail="Application not found")
    job = db["job"].find_one({"_id": ObjectId(app_doc["job_id"])})
    if not job or job.get("recruiter_id") != recruiter["_id"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    db["application"].update_one({"_id": ObjectId(app_id)}, {"$set": {"status": payload.status, "note": payload.note, "updated_at": datetime.now(timezone.utc)}})
    # notify student
    db["notification"].insert_one({
        "user_id": app_doc.get("student_id"),
        "message": f"Your application for {job.get('title')} is {payload.status}",
        "read": False,
        "type": "status",
        "created_at": datetime.now(timezone.utc),
    })
    return {"ok": True}


# ---------- Admin ----------

@app.get("/admin/overview")
def admin_overview(admin = Depends(require_role("admin"))):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    total_users = db["user"].count_documents({})
    total_students = db["user"].count_documents({"role": "student"})
    total_recruiters = db["user"].count_documents({"role": "recruiter"})
    total_jobs = db["job"].count_documents({})
    total_apps = db["application"].count_documents({})
    shortlisted = db["application"].count_documents({"status": "shortlisted"})
    selected = db["application"].count_documents({"status": "selected"})
    rejected = db["application"].count_documents({"status": "rejected"})
    return {
        "users": total_users,
        "students": total_students,
        "recruiters": total_recruiters,
        "jobs": total_jobs,
        "applications": total_apps,
        "shortlisted": shortlisted,
        "selected": selected,
        "rejected": rejected,
    }


@app.get("/admin/users")
def admin_users(admin = Depends(require_role("admin"))):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    users = list(db["user"].find({}).sort("created_at", -1))
    for u in users:
        u["_id"] = str(u["_id"])
        u.pop("password_hash", None)
    return users


@app.delete("/admin/users/{user_id}")
def admin_delete_user(user_id: str, admin = Depends(require_role("admin"))):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    db["user"].delete_one({"_id": oid(user_id)})
    return {"ok": True}


@app.get("/notifications")
def my_notifications(user = Depends(get_user_from_token)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    notes = list(db["notification"].find({"user_id": user["_id"]}).sort("created_at", -1))
    for n in notes:
        n["_id"] = str(n["_id"])
    return notes
