"""兼容原骨架的启动入口：uvicorn main:app。"""
from app.main import app

__all__ = ["app"]
