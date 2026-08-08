from sqlmodel import Session, SQLModel, create_engine

from app.storage import models  # noqa: F401  (registers table metadata on import)


def get_engine(database_path: str):
    return create_engine(f"sqlite:///{database_path}")


def init_db(engine) -> None:
    SQLModel.metadata.create_all(engine)


def get_session(engine) -> Session:
    return Session(engine)
