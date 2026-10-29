from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ApplicationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    base_url: str = Field(min_length=1, max_length=500)
    is_active: bool = True


class ApplicationStatusUpdate(BaseModel):
    is_active: bool


class ApplicationRead(BaseModel):
    id: int
    name: str
    base_url: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
