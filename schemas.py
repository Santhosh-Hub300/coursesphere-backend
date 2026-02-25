from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class CourseCreate(BaseModel):
    title: str
    description: str
    level: str
    duration: str


class CourseResponse(BaseModel):
    id: int
    title: str
    description: str
    level: str
    duration: str

    class Config:
        from_attributes = True