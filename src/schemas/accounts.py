from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators

class UserRegisterSchema(BaseModel):
	email: EmailStr
	password: str

class UserLoginSchema(BaseModel):
	email: EmailStr
	password: str

class TokenDataSchema(BaseModel):
	id: int | None = None
	email: EmailStr | None = None

class UserActivationRequestSchema(BaseModel):
    email: str
    activation_code: str

class MessageResponseSchema(BaseModel):
    message: str
    status: str

class PasswordResetRequestSchema(BaseModel):
    email: str

class PasswordResetCompleteRequestSchema(BaseModel):
    email: str
    reset_code: str
    new_password: str

class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str

class UserLoginRequestSchema(BaseModel):
    email: str
    password: str

class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str

class TokenRefreshResponseSchema(BaseModel):
    access_token: str

class UserRegistrationRequestSchema(BaseModel):
    email: str
    password: str
    full_name: str

class UserRegistrationResponseSchema(BaseModel):
    user_id: int
    email: str
    full_name: str
    message: str