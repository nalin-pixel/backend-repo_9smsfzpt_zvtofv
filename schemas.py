"""
Database Schemas for Internship/Industrial Training Portal

Each Pydantic model represents a collection in MongoDB.
Collection name = lowercase of class name (e.g., User -> "user").
"""
from typing import List, Optional, Literal
from pydantic import BaseModel, Field, EmailStr


class User(BaseModel):
    # Common user fields (Student, Recruiter, Admin)
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="Hashed password")
    role: Literal["student", "recruiter", "admin"] = Field(...)
    is_verified: bool = Field(default=False)
    avatar_url: Optional[str] = None

    # Student specific
    roll: Optional[str] = None
    department: Optional[str] = None
    cgpa: Optional[float] = Field(default=None, ge=0, le=10)
    skills: List[str] = Field(default_factory=list)
    resume_url: Optional[str] = None
    phone: Optional[str] = None
    about: Optional[str] = None

    # Recruiter specific
    company: Optional[str] = None
    designation: Optional[str] = None


class Job(BaseModel):
    title: str
    company: str
    recruiter_id: str
    description: str
    location: str
    stipend_min: Optional[int] = None
    stipend_max: Optional[int] = None
    department: Optional[str] = None
    required_skills: List[str] = Field(default_factory=list)
    conversion_chance: Optional[str] = Field(default=None, description="e.g., High/Medium/Low")
    deadline: Optional[str] = None  # ISO date string
    status: Literal["open", "closed"] = "open"


class Application(BaseModel):
    job_id: str
    student_id: str
    status: Literal["applied", "shortlisted", "selected", "rejected"] = "applied"
    note: Optional[str] = None


class Notification(BaseModel):
    user_id: str
    message: str
    read: bool = False
    type: Optional[str] = None


class PasswordResetToken(BaseModel):
    user_id: str
    token: str
    expires_at: str  # ISO datetime
