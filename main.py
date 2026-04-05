from fastapi import FastAPI, Depends, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from database import SessionLocal, engine
import models
from passlib.context import CryptContext
from jose import jwt

# ================= INIT =================
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# ================= CORS =================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= DB =================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ================= SECURITY =================
SECRET_KEY = "secret"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ================= CREATE ADMIN (🔥 FIXED) =================
def create_admin():
    db = SessionLocal()

    # 🔥 ALWAYS RESET ADMIN (FIX LOGIN ISSUE)
    db.query(models.User).filter(
        models.User.email == "admin@coursesphere.com"
    ).delete()

    db.add(models.User(
        name="Admin",
        email="admin@coursesphere.com",
        password=pwd_context.hash("admin123"),
        role="Admin"
    ))

    db.commit()
    db.close()

create_admin()

# ================= TOKEN =================
def create_token(email: str):
    return jwt.encode({"sub": email}, SECRET_KEY, algorithm=ALGORITHM)

def get_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        email = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]).get("sub")
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(models.User).filter(models.User.email == email).first()

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user

def admin_only(user = Depends(get_user)):
    if user.role != "Admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user

# ================= REGISTER =================
@app.post("/register")
def register(
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    if db.query(models.User).filter(models.User.email == email).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    db.add(models.User(
        name=name,
        email=email,
        password=pwd_context.hash(password),
        role="Student"
    ))
    db.commit()

    return {"message": "User registered successfully"}

# ================= LOGIN =================
@app.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(
        models.User.email == form.username
    ).first()

    if not user or not pwd_context.verify(form.password, user.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    return {
        "access_token": create_token(user.email),
        "token_type": "bearer"
    }

# ================= ME (🔥 IMPORTANT) =================
@app.get("/me")
def get_me(user = Depends(get_user)):
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role
    }

# ================= COURSES =================
@app.get("/courses")
def get_courses(db: Session = Depends(get_db)):
    courses = db.query(models.Course).all()

    return [
        {
            "id": c.id,
            "title": c.title,
            "description": c.description,
            "level": c.level,
            "duration": c.duration
        }
        for c in courses
    ]

@app.post("/courses")
def add_course(
    title: str = Form(...),
    description: str = Form(...),
    level: str = Form(...),
    duration: str = Form(...),
    db: Session = Depends(get_db),
    user = Depends(admin_only)
):
    db.add(models.Course(
        title=title,
        description=description,
        level=level,
        duration=duration
    ))
    db.commit()

    return {"message": "Course added"}

# ================= ENROLL =================
@app.post("/enroll/{id}")
def enroll(id: int, db: Session = Depends(get_db), user = Depends(get_user)):
    db.add(models.Enrollment(user_id=user.id, course_id=id))
    db.commit()
    return {"message": "Enrolled"}

@app.get("/my-courses")
def my_courses(db: Session = Depends(get_db), user = Depends(get_user)):
    enrolls = db.query(models.Enrollment).filter(
        models.Enrollment.user_id == user.id
    ).all()

    result = []

    for e in enrolls:
        c = db.query(models.Course).filter(models.Course.id == e.course_id).first()
        if c:
            result.append({
                "id": c.id,
                "title": c.title,
                "duration": c.duration
            })

    return result
# ================= DELETE COURSE (🔥 ADD THIS) =================
@app.delete("/courses/{id}")
def delete_course(id: int, db: Session = Depends(get_db), user=Depends(admin_only)):
    course = db.query(models.Course).filter(models.Course.id == id).first()

    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    db.delete(course)
    db.commit()

    return {"message": "Course deleted successfully"}
@app.delete("/unenroll/{id}")
def unenroll(id: int, db: Session = Depends(get_db), user=Depends(get_user)):
    e = db.query(models.Enrollment).filter(
        models.Enrollment.user_id == user.id,
        models.Enrollment.course_id == id
    ).first()

    if not e:
        raise HTTPException(status_code=404, detail="Not enrolled")

    db.delete(e)
    db.commit()

    return {"message": "Unenrolled successfully"}