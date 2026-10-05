from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "sqlite:///./forensic.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)

Base = declarative_base()

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String)
    ip_address = Column(String)
    username = Column(String)
    failed_attempts = Column(Integer)
    login_hour = Column(Integer)
    anomaly = Column(Integer)
    risk_score = Column(Integer)

Base.metadata.create_all(bind=engine)