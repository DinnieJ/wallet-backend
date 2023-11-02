from typing import Optional
from sqlalchemy import String, Boolean
from db import Base
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column


class User(Base):
    __tablename__ = "users"
    arbitrary_types_allowed=True
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(30))
    name: Mapped[Optional[str]] = mapped_column(String(256))
    secret: Mapped[str] = mapped_column(String(100), nullable=True)
    otp_setup: Mapped[bool] = mapped_column(Boolean())
