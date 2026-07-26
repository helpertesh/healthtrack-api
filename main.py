from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select

from database.session import create_db_and_tables, get_session
from models.user import (
    User,
    UserCreate,
    UserResponse,
    UserUpdate,
)
from models.health_record import (
    HealthRecord,
    HealthRecordCreate,
    HealthRecordUpdate,
    HealthRecordResponse,
)
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    get_current_active_user,
    get_current_admin,
)

app = FastAPI(
    title="HealthTrack API",
    version="1.0.0"
)


@app.on_event("startup")
def on_startup():
    create_db_and_tables()


# ============================================================
# AUTHENTICATION ENDPOINTS
# ============================================================

@app.post("/register", response_model=UserResponse, status_code=201)
def register_user(
    user_data: UserCreate,
    session: Session = Depends(get_session)
):
    existing_user = session.exec(
        select(User).where(User.username == user_data.username)
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Username already exists"
        )

    existing_email = session.exec(
        select(User).where(User.email == user_data.email)
    ).first()

    if existing_email:
        raise HTTPException(
            status_code=409,
            detail="Email already exists"
        )

    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        full_name=user_data.full_name,
        role=user_data.role,
    )

    session.add(user)
    session.commit()
    session.refresh(user)

    return user


@app.post("/login")
def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session)
):
    user = session.exec(
        select(User).where(User.username == form_data.username)
    ).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    user.last_login = datetime.utcnow()

    session.add(user)
    session.commit()

    access_token = create_access_token(
        data={"sub": user.username}
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


@app.post("/logout")
def logout_user(
    current_user: User = Depends(get_current_user)
):
    return {
        "message": f"Goodbye, {current_user.username}! You have been logged out."
    }


# ============================================================
# PROTECTED ENDPOINTS
# ============================================================

@app.get("/users/me", response_model=UserResponse)
def get_current_user_profile(
    current_user: User = Depends(get_current_active_user)
):
    return current_user


@app.put("/users/me", response_model=UserResponse)
def update_current_user(
    user_data: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session)
):
    if user_data.full_name is not None:
        current_user.full_name = user_data.full_name

    if user_data.email is not None:
        existing_email = session.exec(
            select(User).where(User.email == user_data.email)
        ).first()

        if existing_email and existing_email.id != current_user.id:
            raise HTTPException(
                status_code=409,
                detail="Email already exists"
            )

        current_user.email = user_data.email

    current_user.updated_at = datetime.utcnow()

    session.add(current_user)
    session.commit()
    session.refresh(current_user)

    return current_user


@app.get("/users", response_model=list[UserResponse])
def list_users(
    current_user: User = Depends(get_current_admin),
    session: Session = Depends(get_session)
):
    users = session.exec(select(User)).all()
    return users
@app.post("/records", response_model=HealthRecordResponse, status_code=201)
def create_record(
    record: HealthRecordCreate,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    db_record = HealthRecord(
        patient_name=record.patient_name,
        diagnosis=record.diagnosis,
        treatment=record.treatment,
        owner_id=current_user.id,
    )

    session.add(db_record)
    session.commit()
    session.refresh(db_record)

    return db_record


@app.get("/records", response_model=list[HealthRecordResponse])
def get_records(
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    if current_user.role == "admin":
        return session.exec(select(HealthRecord)).all()

    return session.exec(
        select(HealthRecord).where(
            HealthRecord.owner_id == current_user.id
        )
    ).all()


@app.get("/records/{record_id}", response_model=HealthRecordResponse)
def get_record(
    record_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    record = session.get(HealthRecord, record_id)

    if not record:
        raise HTTPException(404, "Record not found")

    if (
        current_user.role != "admin"
        and record.owner_id != current_user.id
    ):
        raise HTTPException(403, "Access denied")

    return record


@app.put("/records/{record_id}", response_model=HealthRecordResponse)
def update_record(
    record_id: int,
    record_data: HealthRecordUpdate,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    record = session.get(HealthRecord, record_id)

    if not record:
        raise HTTPException(404, "Record not found")

    if (
        current_user.role != "admin"
        and record.owner_id != current_user.id
    ):
        raise HTTPException(403, "Access denied")

    if record_data.patient_name is not None:
        record.patient_name = record_data.patient_name

    if record_data.diagnosis is not None:
        record.diagnosis = record_data.diagnosis

    if record_data.treatment is not None:
        record.treatment = record_data.treatment

    session.add(record)
    session.commit()
    session.refresh(record)

    return record


@app.delete("/records/{record_id}")
def delete_record(
    record_id: int,
    current_user: User = Depends(get_current_admin),
    session: Session = Depends(get_session),
):
    record = session.get(HealthRecord, record_id)

    if not record:
        raise HTTPException(404, "Record not found")

    session.delete(record)
    session.commit()

    return {"message": "Record deleted successfully"}

