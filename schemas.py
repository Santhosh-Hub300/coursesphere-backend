from pydantic import BaseModel, EmailStr

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str


class CourseResponse(BaseModel):
    id: int
    title: str
    description: str
    level: str
    duration: str

    class Config:
        from_attributes = True