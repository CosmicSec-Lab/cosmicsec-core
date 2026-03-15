"""Core ORM models for baseline service entities."""

from sqlalchemy import Boolean, Column, DateTime, Integer, String, func

from .db import Base


class UserModel(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    email = Column(String, unique=True, nullable=False, index=True)
    full_name = Column(String, nullable=False)
    role = Column(String, nullable=False, default="user")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ScanModel(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True)
    target = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False, default="pending")
    progress = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
