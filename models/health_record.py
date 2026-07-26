from datetime import datetime
from typing import Optional

from sqlmodel import SQLModel, Field


class HealthRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    patient_name: str
    diagnosis: str
    treatment: str

    created_at: datetime = Field(default_factory=datetime.utcnow)

    owner_id: int = Field(foreign_key="user.id")


class HealthRecordCreate(SQLModel):
    patient_name: str
    diagnosis: str
    treatment: str


class HealthRecordUpdate(SQLModel):
    patient_name: Optional[str] = None
    diagnosis: Optional[str] = None
    treatment: Optional[str] = None


class HealthRecordResponse(SQLModel):
    id: int
    patient_name: str
    diagnosis: str
    treatment: str
    created_at: datetime
    owner_id: int