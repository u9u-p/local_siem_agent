from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

from app.storage import models  # noqa: F401  (registers table metadata on import)


def get_engine(database_path: str):
    parent = Path(database_path).parent
    # Bare filenames yield Path("."), which always exists; ":memory:" likewise has
    # no directory component, so neither needs (or gets) a mkdir.
    if str(parent) not in (".", ""):
        parent.mkdir(parents=True, exist_ok=True)
    return create_engine(f"sqlite:///{database_path}")


def init_db(engine) -> None:
    SQLModel.metadata.create_all(engine)


def get_session(engine) -> Session:
    return Session(engine)
