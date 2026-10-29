from backend.database import engine
from backend.models.database import Base


def init_database():
    Base.metadata.create_all(bind=engine)
    print("SentinelX database tables created successfully.")


if __name__ == "__main__":
    init_database()