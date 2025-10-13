# from fastapi import FastAPI, HTTPException, Depends
# from fastapi.middleware.cors import CORSMiddleware
# from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# from pydantic import BaseModel, EmailStr, constr
# import bcrypt
# import jwt
# import uuid
# import os  # Keep os, remove sys if not used
# from pymongo import MongoClient
# from dotenv import load_dotenv
# from datetime import datetime, timedelta
# from fastapi import UploadFile, File,status
# from smartmodel import DocumentQA  # Import class (assumes smartmodel.py in root)

# # Remove this line: sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# # Rest of your code unchanged...

# # sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# # ------------------------
# # App Setup
# # ------------------------
# app = FastAPI()

# security = HTTPBearer()  # For future token validation

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=[
#         "http://localhost:3000",
#         "http://127.0.0.1:3000",
#         "http://localhost:5173",
#         "http://127.0.0.1:5173",
#         "http://localhost:8000",
#         "http://127.0.0.1:8000",
#         "http://localhost:5000",      # ✅ ADD THIS
#         "http://127.0.0.1:5000",      # ✅ AND THIS
#     ],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )



# # ------------------------
# # Environment Variables & DB
# # ------------------------
# load_dotenv()
# MONGO_URI = os.getenv("MONGO_URI")
# DB_NAME = os.getenv("DB_NAME", "smartdocq")
# JWT_SECRET = os.getenv("JWT_SECRET", "your_jwt_secret")
# JWT_EXPIRY_MINUTES = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))

# client = MongoClient(MONGO_URI)
# db = client[DB_NAME]
# users_collection = db["users"]

# # ------------------------
# # Global QA (RAM cache)
# # ------------------------
# qa_system = DocumentQA()

# # ------------------------
# # Models
# # ------------------------
# class SignupModel(BaseModel):
#     full_name: constr(min_length=2)
#     email: EmailStr
#     password: constr(min_length=8)
#     confirm_password: constr(min_length=8)

# class LoginModel(BaseModel):
#     email: EmailStr
#     password: constr(min_length=8)

# class ChatRequest(BaseModel):
#     question: str

# # ------------------------
# # Helpers
# # ------------------------
# def create_jwt(user: dict):
#     payload = {
#         "id": user["id"],
#         "email": user["email"],
#         "full_name": user["full_name"],
#         "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRY_MINUTES),
#     }
#     return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

# # ------------------------
# # Routes
# # ------------------------
# @app.post("/api/signup")
# def signup(data: SignupModel):
#     if data.password != data.confirm_password:
#         raise HTTPException(status_code=400, detail="Passwords do not match.")
#     if not any(c.isalpha() for c in data.password) or not any(c.isdigit() for c in data.password):
#         raise HTTPException(status_code=400, detail="Password must contain letters and numbers.")

#     if users_collection.find_one({"email": data.email}):
#         raise HTTPException(status_code=409, detail="Email already registered.")

#     password_hash = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()

#     user_id = str(uuid.uuid4())
#     new_user = {
#         "id": user_id,
#         "full_name": data.full_name,
#         "email": data.email,
#         "password_hash": password_hash,
#     }
#     users_collection.insert_one(new_user)

#     return {"message": "User created successfully", "user": {"id": user_id, "full_name": data.full_name, "email": data.email}}

# @app.post("/api/login")
# def login(data: LoginModel):
#     user = users_collection.find_one({"email": data.email})
#     if not user:
#         raise HTTPException(status_code=401, detail="Invalid email or password.")

#     if not bcrypt.checkpw(data.password.encode(), user["password_hash"].encode()):
#         raise HTTPException(status_code=401, detail="Invalid email or password.")

#     token = create_jwt(user)

#     return {
#         "message": "Login successful",
#         "token": token,
#         "user": {"id": user["id"], "email": user["email"], "full_name": user["full_name"]},
#     }

# @app.post("/api/logout")
# def logout():
#     """Clear RAM cache on logout"""
#     result = qa_system.clear_cache()
#     return {"message": "Logged out successfully", "cache": result}

# @app.post("/api/upload")
# async def upload_document(file: UploadFile = File(...)):
#     if not file.filename.lower().endswith(('.pdf', '.docx', '.txt')):
#         raise HTTPException(status_code=400, detail="Unsupported file type")

#     os.makedirs("temp_uploads", exist_ok=True)
#     file_path = os.path.join("temp_uploads", file.filename)
#     try:
#         content = await file.read()
#         with open(file_path, "wb") as f:
#             f.write(content)
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to save upload: {e}")

#     try:
#         result = qa_system.load_document(file_path)
#         # remove file after processing
#         if os.path.exists(file_path):
#             os.remove(file_path)
#         return {"message": "Document processed successfully", "status": result}
#     except Exception as e:
#         if os.path.exists(file_path):
#             os.remove(file_path)
#         raise HTTPException(status_code=500, detail=f"Processing failed: {str(e)}")

# @app.post("/api/chat")
# async def chat(data: ChatRequest):
#     try:
#         # simple sanity check
#         if not data.question or not data.question.strip():
#             raise HTTPException(status_code=400, detail="Question cannot be empty")

#         answer = qa_system.ask_question(data.question)
#         # consistent JSON structure
#         return {"answer": answer}
#     except HTTPException:
#         raise
#     except Exception as e:
#         # Catch-all - return 500 and helpful message
#         raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
    
# @app.get("/api/smart")
# def smart_check():
#     return {"status": "ok"}


# main.py
# from fastapi import FastAPI, HTTPException, Depends
# from fastapi.middleware.cors import CORSMiddleware
# from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# from pydantic import BaseModel, EmailStr, constr
# import bcrypt
# import jwt
# import uuid
# import os
# from pymongo import MongoClient
# from dotenv import load_dotenv
# from datetime import datetime, timedelta
# from fastapi import UploadFile, File, status
# from smartmodel import DocumentQA  # Import class (assumes smartmodel.py in root)
# from typing import Dict, Any  # Added missing import

# # ------------------------
# # App Setup
# # ------------------------
# app = FastAPI()

# security = HTTPBearer()

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# @app.get("/")
# def read_root():
#     return {"message": "SmartDocQ Backend running."}

# # ------------------------
# # Environment Variables & DB
# # ------------------------
# load_dotenv()
# MONGO_URI = os.getenv("MONGO_URI")
# DB_NAME = os.getenv("DB_NAME", "smartdocq")
# JWT_SECRET = os.getenv("JWT_SECRET", "your_jwt_secret")
# JWT_EXPIRY_MINUTES = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))

# client = MongoClient(MONGO_URI)
# db = client[DB_NAME]
# users_collection = db["users"]

# # ------------------------
# # Global QA (RAM cache)
# # ------------------------
# qa_system = DocumentQA()

# # ------------------------
# # Interview Manager (RAM cache + persistent save on completion)
# # ------------------------
# INTERVIEW_SESSIONS: Dict[str, Dict[str, Any]] = {}

# # ------------------------
# # Models
# # ------------------------
# class SignupModel(BaseModel):
#     full_name: constr(min_length=2)
#     email: EmailStr
#     password: constr(min_length=8)
#     confirm_password: constr(min_length=8)

# class LoginModel(BaseModel):
#     email: EmailStr
#     password: constr(min_length=8)

# class ChatRequest(BaseModel):
#     question: str

# # ------------------------
# # Helpers
# # ------------------------
# def create_jwt(user: dict):
#     payload = {
#         "id": user["id"],
#         "email": user["email"],
#         "full_name": user["full_name"],
#         "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRY_MINUTES),
#     }
#     return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

# # ------------------------
# # Routes
# # ------------------------
# @app.post("/api/signup")
# def signup(data: SignupModel):
#     if data.password != data.confirm_password:
#         raise HTTPException(status_code=400, detail="Passwords do not match.")
#     if not any(c.isalpha() for c in data.password) or not any(c.isdigit() for c in data.password):
#         raise HTTPException(status_code=400, detail="Password must contain letters and numbers.")

#     if users_collection.find_one({"email": data.email}):
#         raise HTTPException(status_code=409, detail="Email already registered.")

#     password_hash = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()

#     user_id = str(uuid.uuid4())
#     new_user = {
#         "id": user_id,
#         "full_name": data.full_name,
#         "email": data.email,
#         "password_hash": password_hash,
#     }
#     users_collection.insert_one(new_user)

#     return {"message": "User created successfully", "user": {"id": user_id, "full_name": data.full_name, "email": data.email}}

# @app.post("/api/login")
# def login(data: LoginModel):
#     user = users_collection.find_one({"email": data.email})
#     if not user:
#         raise HTTPException(status_code=401, detail="Invalid email or password.")

#     if not bcrypt.checkpw(data.password.encode(), user["password_hash"].encode()):
#         raise HTTPException(status_code=401, detail="Invalid email or password.")

#     token = create_jwt(user)

#     return {
#         "message": "Login successful",
#         "token": token,
#         "user": {"id": user["id"], "email": user["email"], "full_name": user["full_name"]},
#     }

# @app.post("/api/logout")
# def logout():
#     """Clear RAM cache on logout"""
#     result = qa_system.clear_cache()
#     return {"message": "Logged out successfully", "cache": result}

# @app.post("/api/upload")
# async def upload_document(file: UploadFile = File(...)):
#     if not file.filename.lower().endswith(('.pdf', '.docx', '.txt')):
#         raise HTTPException(status_code=400, detail="Unsupported file type")

#     os.makedirs("temp_uploads", exist_ok=True)
#     file_path = os.path.join("temp_uploads", file.filename)
#     try:
#         content = await file.read()
#         with open(file_path, "wb") as f:
#             f.write(content)
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to save upload: {e}")

#     try:
#         result = qa_system.load_document(file_path)
#         if os.path.exists(file_path):
#             os.remove(file_path)
#         return {"message": "Document processed successfully", "status": result}
#     except Exception as e:
#         if os.path.exists(file_path):
#             os.remove(file_path)
#         raise HTTPException(status_code=500, detail=f"Processing failed: {str(e)}")

# @app.post("/api/chat")
# async def chat(data: ChatRequest):
#     try:
#         if not data.question or not data.question.strip():
#             raise HTTPException(status_code=400, detail="Question cannot be empty")

#         answer = qa_system.ask_question(data.question)
#         return {"answer": answer}
#     except HTTPException:
#         raise
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# # ------------------------
# # SmartInterview Class (already defined locally)
# # ------------------------
# class SmartInterview:
#     def init(self):
#         pass
#     # Add methods and logic for the class here


# main.py
import os
import uuid
import json
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    UploadFile,
    File,
    status,
    Body,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, constr
import bcrypt
import jwt
from dotenv import load_dotenv
from pymongo import MongoClient

# Import your existing DocumentQA (unchanged) and InterviewCopilot (from smartinterview.py)
from smartmodel import DocumentQA  # existing model import (unchanged)
from smartinterview import InterviewCopilot  # assumes smartinterview.py is next to this file

# ------------------------
# App Setup
# ------------------------
app = FastAPI(title="SmartDocQ Backend", version="1.0")

security = HTTPBearer()  # placeholder for token checks

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=[
#         "http://localhost:3000",
#         "http://127.0.0.1:3000",
#         "http://localhost:5173",
#         "http://127.0.0.1:5173",
#         "http://localhost:8000",
#         "http://127.0.0.1:8000",
#         "http://localhost:5000",
#         "http://127.0.0.1:5000",
#     ],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )
# from fastapi.middleware.cors import CORSMiddleware

from fastapi import FastAPI, Form
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Allow frontend origin
origins = [
    "http://127.0.0.1:5000",
    "http://localhost:5000",
    # add more origins if needed
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # or ["*"] to allow all origins (not recommended for prod)
    allow_credentials=True,
    allow_methods=["*"],    # GET, POST, PUT, DELETE etc
    allow_headers=["*"],    # allow all headers
)



# ------------------------
# Environment & DB
# ------------------------
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "smartdocq")
JWT_SECRET = os.getenv("JWT_SECRET", "your_jwt_secret")
JWT_EXPIRY_MINUTES = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
users_collection = db["users"]
interviews_collection = db["interviews"]

# ------------------------
# Existing RAM QA
# ------------------------
qa_system = DocumentQA()  # unchanged, used by /api/upload and /api/chat

# ------------------------
# Interview Manager (RAM cache + persistent save on completion)
# ------------------------
# Note: In production use Redis or DB-backed session store for multiple workers.
INTERVIEW_SESSIONS: Dict[str, Dict[str, Any]] = {}

# ------------------------
# Pydantic Models
# ------------------------
class SignupModel(BaseModel):
    full_name: constr(min_length=2)
    email: EmailStr
    password: constr(min_length=8)
    confirm_password: constr(min_length=8)

class LoginModel(BaseModel):
    email: EmailStr
    password: constr(min_length=8)

class ChatRequest(BaseModel):
    question: str

class StartInterviewResponse(BaseModel):
    session_id: str
    questions: List[str]
    structured_questions: Optional[List[dict]] = None

class SubmitAnswersRequest(BaseModel):
    answers: List[str]

class InterviewStatusResponse(BaseModel):
    session_id: str
    created_at: datetime
    num_questions: int
    level: str
    questions_generated: bool
    completed: bool
    score: Optional[float] = None

# ------------------------
# Helpers
# ------------------------
def create_jwt(user: dict) -> str:
    payload = {
        "id": user["id"],
        "email": user["email"],
        "full_name": user["full_name"],
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRY_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_token(creds: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    Basic token verifier. For now we decode JWT and return payload.
    If token invalid -> raise HTTPException(401).
    """
    token = creds.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def save_interview_report_to_db(session: Dict[str, Any]) -> None:
    """Save completed interview report to MongoDB interviews collection."""
    try:
        record = {
            "session_id": session["session_id"],
            "user": session.get("user"),  # if you tracked user info, else None
            "created_at": session["created_at"],
            "num_questions": session["num_questions"],
            "level": session["level"],
            "questions": session["questions"],
            "answers": session.get("answers"),
            "feedback": session.get("feedback"),
            "avg_score": session.get("avg_score"),
        }
        interviews_collection.insert_one(record)
    except Exception as e:
        # Log error in production (here we just raise)
        raise

# ------------------------
# Routes (existing ones largely unchanged)
# ------------------------
@app.post("/api/signup")
def signup(data: SignupModel):
    if data.password != data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")
    if not any(c.isalpha() for c in data.password) or not any(c.isdigit() for c in data.password):
        raise HTTPException(status_code=400, detail="Password must contain letters and numbers.")

    if users_collection.find_one({"email": data.email}):
        raise HTTPException(status_code=409, detail="Email already registered.")

    password_hash = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()

    user_id = str(uuid.uuid4())
    new_user = {
        "id": user_id,
        "full_name": data.full_name,
        "email": data.email,
        "password_hash": password_hash,
    }
    users_collection.insert_one(new_user)

    return {"message": "User created successfully", "user": {"id": user_id, "full_name": data.full_name, "email": data.email}}

@app.post("/api/login")
def login(data: LoginModel):
    user = users_collection.find_one({"email": data.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not bcrypt.checkpw(data.password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    token = create_jwt(user)

    return {
        "message": "Login successful",
        "token": token,
        "user": {"id": user["id"], "email": user["email"], "full_name": user["full_name"]},
    }

@app.post("/api/logout")
def logout():
    """Clear RAM cache on logout (existing behaviour)"""
    result = qa_system.clear_cache()
    return {"message": "Logged out successfully", "cache": result}

@app.post("/api/upload")
async def upload_document(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(('.pdf', '.docx', '.txt')):
        raise HTTPException(status_code=400, detail="Unsupported file type")

    os.makedirs("temp_uploads", exist_ok=True)
    file_path = os.path.join("temp_uploads", file.filename)
    try:
        content = await file.read()
        with open(file_path, "wb") as f:
            f.write(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save upload: {e}")

    try:
        result = qa_system.load_document(file_path)
        # remove file after processing
        if os.path.exists(file_path):
            os.remove(file_path)
        return {"message": "Document processed successfully", "status": result}
    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=500, detail=f"Processing failed: {str(e)}")

@app.post("/api/chat")
async def chat(data: ChatRequest):
    try:
        if not data.question or not data.question.strip():
            raise HTTPException(status_code=400, detail="Question cannot be empty")
        answer = qa_system.ask_question(data.question)
        return {"answer": answer}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
    
@app.get("/api/smart")
def smart_check():
    return {"status": "ok"}

# ------------------------
# Interview Endpoints (new)
# ------------------------
@app.post("/api/interview/start", response_model=StartInterviewResponse)
async def start_interview(
    file: UploadFile = File(...),
    num_questions: int = Form(...),
    level: Optional[str] = Form(None),
    question_type: Optional[str] = Form(None),
    creds: Optional[HTTPAuthorizationCredentials] = Depends(security),
):
    if num_questions <= 0 or num_questions > 50:
        raise HTTPException(status_code=400, detail="num_questions must be between 1 and 50")

    # Determine level: allow 'level' or map from question_type if provided
    if question_type:
        # normalize common qtypes to levels
        qmap = {
            "mcq": "easy",
            "hr": "easy",
            "technical": "medium",
            "theory": "hard",
        }
        level = qmap.get(question_type.lower(), (level or "medium"))

    level = (level or "medium").lower()
    if level not in ("easy", "medium", "hard"):
        raise HTTPException(status_code=400, detail="level must be one of: easy, medium, hard")

    user_payload = None
    try:
        user_payload = verify_token(creds) if creds else None
    except HTTPException:
        user_payload = None

    if not file.filename.lower().endswith(('.pdf', '.docx', '.txt')):
        raise HTTPException(status_code=400, detail="Unsupported file type")

    os.makedirs("temp_uploads", exist_ok=True)
    file_path = os.path.join("temp_uploads", f"{uuid.uuid4()}_{file.filename}")

    try:
        content = await file.read()
        with open(file_path, "wb") as f:
            f.write(content)
    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=500, detail=f"Failed to save upload: {e}")

    # ✅ Use InterviewCopilot instead of dummy placeholder
    try:
        interview_bot = InterviewCopilot()
        interview_bot.load_document(file_path)
        # Pass question_type (qtype) through for more specific generation when available
        questions = interview_bot.generate_questions(num_questions=num_questions, level=level, qtype=question_type)
    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=500, detail=f"Question generation failed: {str(e)}")

    # Create session
    session_id = str(uuid.uuid4())
    INTERVIEW_SESSIONS[session_id] = {
        "session_id": session_id,
        "created_at": datetime.utcnow(),
        "num_questions": num_questions,
        "level": level,
        "questions": questions,
        "structured_questions": getattr(interview_bot, "structured_questions", None),
        "interview_bot": interview_bot,  # store for later evaluation
        "answers": None,
        "feedback": None,
        "avg_score": None,
        "completed": False,
        "user": user_payload,
    }

    if os.path.exists(file_path):
        os.remove(file_path)

    return StartInterviewResponse(session_id=session_id, questions=questions, structured_questions=INTERVIEW_SESSIONS[session_id].get("structured_questions"))


@app.post("/api/interview/{session_id}/submit")
def submit_answers(session_id: str, payload: SubmitAnswersRequest):
    """
    Submit ALL answers at once (client-side collects them and sends list).
    Backend evaluates using the InterviewCopilot.evaluate_answers method.
    """
    session = INTERVIEW_SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.get("completed"):
        raise HTTPException(status_code=400, detail="Session already completed")

    answers = payload.answers
    if not isinstance(answers, list) or len(answers) != len(session["questions"]):
        raise HTTPException(status_code=400, detail="Number of answers must match number of questions")

    interview_bot: InterviewCopilot = session.get("interview_bot")
    if not interview_bot:
        raise HTTPException(status_code=500, detail="Interview bot lost from session (server restart?)")

    # Evaluate answers
    try:
        structured = session.get("structured_questions")
        if structured and isinstance(structured, list) and all(isinstance(s, dict) and s.get("correct") for s in structured):
            # Quick MCQ grading using structured 'correct' field
            feedback = []
            total = 0
            for idx, (q, ans) in enumerate(zip(structured, answers)):
                correct = str(q.get("correct", "")).strip()
                # Compare normalized strings
                user_sel = str(ans or "").strip()
                score = 10 if user_sel and (user_sel == correct or user_sel.startswith(correct.split(")")[0])) else 0
                fb_text = "Correct." if score == 10 else f"Incorrect. Correct: {correct}"
                feedback.append({
                    "question": q.get("question", ""),
                    "user_answer": user_sel,
                    "score": score,
                    "feedback": fb_text,
                    "correct_answer": correct,
                })
                total += score
            avg_score = round(total / len(structured), 2) if structured else 0
        else:
            avg_score, feedback = interview_bot.evaluate_answers(answers)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Evaluation failed: {str(e)}")

    # Save results into session and mark completed
    session["answers"] = answers
    session["feedback"] = feedback
    session["avg_score"] = avg_score
    session["completed"] = True
    # Optionally drop the in-memory bot instance to free RAM (keep if you want further interactions)
    session.pop("interview_bot", None)

    # Persist final report to DB (non-blocking in production — but here we write synchronously)
    try:
        save_interview_report_to_db(session)
    except Exception:
        # ignore DB write failures for now but log in production
        pass

    # Return the feedback to the client (last review page)
    return {"session_id": session_id, "avg_score": avg_score, "feedback": feedback}

@app.get("/api/interview/{session_id}/review")
def interview_review(session_id: str):
    """
    Retrieve review (questions, answers, feedback, avg score) for a completed session.
    """
    session = INTERVIEW_SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if not session.get("completed"):
        raise HTTPException(status_code=400, detail="Session not yet completed")
    return {
        "session_id": session_id,
        "created_at": session["created_at"],
        "num_questions": session["num_questions"],
        "level": session["level"],
        "questions": session["questions"],
        "answers": session["answers"],
        "feedback": session["feedback"],
        "avg_score": session["avg_score"],
    }

# ------------------------
# Health & Misc
# ------------------------
@app.get("/")
def read_root():
    return {"message": "SmartDocQ Backend running."}