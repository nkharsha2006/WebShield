from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ScanRunRead(BaseModel):
    id: int
    application_id: int
    status: str
    scanner: str
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None

    model_config = ConfigDict(from_attributes=True)
