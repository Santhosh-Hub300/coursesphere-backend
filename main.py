from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from typing import Optional
import os

import models
import schemas
from database import SessionLocal, engine

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# =============================
# ✅ UNIVERSAL CORS (PRODUCTION SAFE)
# =============================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # 🔥 allow all origins (simple + safe for your project)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================
# DATABASE
# =============================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =============================
# SECURITY
# =============================
SECRET_KEY = os.getenv("SECRET_KEY", "dev_secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme),
                     db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(models.User).filter(models.User.email == email).first()

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user

def require_admin(user: models.User = Depends(get_current_user)):
    if user.role != "Admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# =============================
# ROOT
# =============================
@app.get("/")
def root():
    return {"message": "CourseSphere Backend Running"}

# =============================
# REGISTER
# =============================
@app.post("/register")
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):

    existing = db.query(models.User).filter(
        models.User.email == user.email
    ).first()

    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed = pwd_context.hash(user.password)

    # 🔥 AUTO ADMIN DOMAIN LOGIC
    role = "Student"
    if user.email.endswith("@coursesphere.com"):
        role = "Admin"

    new_user = models.User(
        name=user.name,
        email=user.email,
        password=hashed,
        role=role
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User registered successfully"}

# =============================
# LOGIN
# =============================
@app.post("/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(),
          db: Session = Depends(get_db)):

    db_user = db.query(models.User).filter(
        models.User.email == form_data.username
    ).first()

    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid email or password")

    if not pwd_context.verify(form_data.password, db_user.password):
        raise HTTPException(status_code=400, detail="Invalid email or password")

    access_token = create_access_token(data={"sub": db_user.email})

    return {"access_token": access_token, "token_type": "bearer"}

# =============================
# ME
# =============================
@app.get("/me")
def me(user: models.User = Depends(get_current_user)):
    return {
        "name": user.name,
        "email": user.email,
        "role": user.role
    }

# =============================
# GET COURSES
# =============================
@app.get("/courses", response_model=list[schemas.CourseResponse])
def get_courses(search: Optional[str] = "",
                skip: int = 0,
                limit: int = 20,
                db: Session = Depends(get_db)):
    return db.query(models.Course).filter(
        models.Course.title.contains(search)
    ).offset(skip).limit(limit).all()

# =============================
# CREATE COURSE (ADMIN ONLY)
# =============================
@app.post("/courses")
def create_course(
    course: schemas.CourseCreate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin)
):

    new_course = models.Course(
        title=course.title,
        description=course.description,
        level=course.level,
        duration=course.duration
    )

    db.add(new_course)
    db.commit()
    db.refresh(new_course)

    return {"message": "Course created successfully"}

# =============================
# ENROLL
# =============================
@app.post("/enroll/{course_id}")
def enroll(course_id: int,
           db: Session = Depends(get_db),
           user: models.User = Depends(get_current_user)):

    course = db.query(models.Course).filter(
        models.Course.id == course_id
    ).first()

    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    existing = db.query(models.Enrollment).filter(
        models.Enrollment.user_id == user.id,
        models.Enrollment.course_id == course_id
    ).first()

    if existing:
        raise HTTPException(status_code=400, detail="Already enrolled")

    enrollment = models.Enrollment(
        user_id=user.id,
        course_id=course_id
    )

    db.add(enrollment)
    db.commit()

    return {"message": "Enrolled successfully"}

# =============================
# MY COURSES
# =============================
@app.get("/my-courses")
def my_courses(db: Session = Depends(get_db),
               user: models.User = Depends(get_current_user)):

    enrollments = db.query(models.Enrollment).filter(
        models.Enrollment.user_id == user.id
    ).all()

    result = []

    for e in enrollments:
        course = db.query(models.Course).filter(
            models.Course.id == e.course_id
        ).first()

        result.append({
            "id": course.id,
            "title": course.title,
            "description": course.description,
            "level": course.level,
            "duration": course.duration
        })

    return result

# =============================
# ADMIN STATS
# =============================
@app.get("/admin/stats")
def admin_stats(db: Session = Depends(get_db),
                admin: models.User = Depends(require_admin)):

    return {
        "total_users": db.query(models.User).count(),
        "total_courses": db.query(models.Course).count(),
        "total_enrollments": db.query(models.Enrollment).count()
    }
# =============================
# ADMIN - GET ALL STUDENTS + ENROLLMENTS
# =============================
@app.get("/admin/students")
def get_all_students(
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin)
):
    students = db.query(models.User).filter(
        models.User.role == "Student"
    ).all()

    result = []

    for student in students:
        enrollments = db.query(models.Enrollment).filter(
            models.Enrollment.user_id == student.id
        ).all()

        courses = []

        for e in enrollments:
            course = db.query(models.Course).filter(
                models.Course.id == e.course_id
            ).first()

            if course:
                courses.append(course.title)

        result.append({
            "id": student.id,
            "name": student.name,
            "email": student.email,
            "courses": courses
        })

    return result