# smartinterview.py
import os
import re
import json
import fitz
import docx
import numpy as np
import faiss
from typing import List, Optional, Tuple
from sentence_transformers import SentenceTransformer
import google.generativeai as genai
import logging
from dotenv import load_dotenv

# -----------------------------
# Environment Setup
# -----------------------------
load_dotenv()
API_KEY = os.getenv("GOOGLE_API_KEY")
if not API_KEY:
    raise ValueError("GOOGLE_API_KEY not set in environment")

genai.configure(api_key=API_KEY)
EMBED_MODEL_NAME = "all-MiniLM-L6-v2"
_embed_model = SentenceTransformer(EMBED_MODEL_NAME)


# -----------------------------
# Document Utilities
# -----------------------------
def read_pdf(path: str) -> str:
    """Reads a PDF file and returns its text."""
    doc = fitz.open(path)
    return "\n".join([p.get_text() for p in doc])

def read_docx(path: str) -> str:
    """Reads a DOCX file and returns its text."""
    d = docx.Document(path)
    return "\n".join([p.text for p in d.paragraphs])

def read_txt(path: str) -> str:
    """Reads a plain text file and returns its content."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def read_document_file(path: str) -> str:
    """Reads any supported document type and returns text."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pdf": return read_pdf(path)
    if ext == ".docx": return read_docx(path)
    if ext == ".txt": return read_txt(path)
    raise ValueError(f"Unsupported file type: {ext}")


# -----------------------------
# Text Chunking and Embeddings
# -----------------------------
def chunk_text(text: str, chunk_size: int = 300, overlap: int = 50) -> List[str]:
    """Splits text into overlapping chunks for semantic embedding."""
    words = text.split()
    chunks = []
    i = 0
    while i < len(words):
        j = min(i + chunk_size, len(words))
        chunk = " ".join(words[i:j]).strip()
        if chunk:
            chunks.append(chunk)
        i += chunk_size - overlap
    return chunks

def get_embeddings(texts: List[str]) -> np.ndarray:
    """Generates embeddings for a list of texts."""
    arr = _embed_model.encode(texts, show_progress_bar=False)
    if isinstance(arr, list):
        arr = np.array(arr)
    return np.asarray(arr).astype("float32")

def build_faiss_index(chunks: List[str]) -> Tuple[faiss.IndexFlatL2, List[str]]:
    """Builds a FAISS index from a list of text chunks."""
    embeddings = get_embeddings(chunks)
    dim = embeddings.shape[1]
    index = faiss.IndexFlatL2(dim)
    index.add(embeddings)
    return index, chunks


# -----------------------------
# Gemini Helper
# -----------------------------
def gemini_generate(prompt: str) -> str:
    """Uses Google Gemini to generate a text response."""
    try:
        model = genai.GenerativeModel("gemini-2.0-flash")
        res = model.generate_content(prompt)
        # Log for debugging (avoid logging prompt with secrets)
        logging.debug("gemini_generate: received response object type: %s", type(res))
        if hasattr(res, "text") and res.text:
            logging.debug("gemini_generate: text length=%d", len(res.text))
            return res.text.strip()
        elif hasattr(res, "candidates") and res.candidates:
            # candidates can be a list of candidate objects
            first = res.candidates[0]
            content = getattr(first, "content", None) or getattr(first, "text", None) or str(first)
            logging.debug("gemini_generate: candidate content length=%d", len(str(content)))
            return str(content).strip()
        else:
            logging.debug("gemini_generate: unexpected response, returning str(res)")
            return str(res)
    except Exception as e:
        logging.exception("gemini_generate error")
        return f"Gemini error: {repr(e)}"


# -----------------------------
# Interview Copilot
# -----------------------------
class InterviewCopilot:
    """
    AI Interview assistant that:
    1. Loads a document and creates embeddings
    2. Generates interview questions from context
    3. Evaluates user answers and gives feedback
    """

    def __init__(self):
        self.index: Optional[faiss.IndexFlatL2] = None
        self.chunks: Optional[List[str]] = None
        self.questions: List[str] = []
        self.feedback: List[dict] = []
        self.structured_questions: Optional[List[dict]] = None

    # -------------------------
    # Load Document
    # -------------------------
    def load_document(self, file_path: str) -> str:
        """Loads and indexes the given document."""
        text = read_document_file(file_path)
        chunks = chunk_text(text, chunk_size=300, overlap=50)
        self.index, self.chunks = build_faiss_index(chunks)
        return f"✅ Document loaded successfully. {len(self.chunks)} chunks indexed."

    # -------------------------
    # Question Generation
    # -------------------------
    def generate_questions(self, num_questions: int = 5, level: str = "medium", qtype: Optional[str] = None, **kwargs) -> List[str]:
        """Generates interview questions from document content."""
        if not self.chunks:
            raise ValueError("Please load a document first.")
        # Support legacy 'qtype' parameter by mapping it to level if provided
        if (level is None or str(level).strip() == "") and qtype:
            level = qtype

        context = "\n\n".join(self.chunks[:6])

        # If a specific qtype is requested, ask the model for a strict JSON array of questions
        if qtype:
            qtype_lower = qtype.lower()
            # build type-specific JSON schema and instruction
            if qtype_lower == "mcq":
                instr = (
                    "Return a JSON array with exactly {n} MCQ objects based ONLY on the Document Context. "
                    "Each object must have: question (string), options (array of 4 option strings labeled 'A) ...', 'B) ...'), and correct (the correct option label and text, e.g. 'B) Option text'). "
                )
            elif qtype_lower == "hr":
                instr = (
                    "Return a JSON array with exactly {n} HR (behavioral) question objects. "
                    "Each object must have: question (string) and if helpful a short scenario field."
                )
            elif qtype_lower == "technical":
                instr = (
                    "Return a JSON array with exactly {n} Technical question objects. "
                    "Each object must have: question (string) and difficulty ('easy'|'medium'|'hard')."
                )
            else:
                instr = (
                    "Return a JSON array with exactly {n} question objects suitable for the requested type. "
                    "Each object must have: question (string)."
                )

            prompt = f"""
You are an interview question generator. Follow these rules strictly.

Document Context:
{context}

{instr}

Return ONLY valid JSON (no surrounding text). The JSON must be an array with exactly {num_questions} elements. Example for MCQ:
[{{"question":"...","options":["A) ...","B) ...","C) ...","D) ..."],"correct":"B) ..."}}, ...]
""".replace("{n}", str(num_questions)).replace("{instr}", instr)

            result = gemini_generate(prompt)

            # Try to extract JSON from the model output
            try:
                match = re.search(r"\[\s*\{.*\}\s*\]", result, re.S)
                json_text = match.group(0) if match else result
                parsed = json.loads(json_text)
                if isinstance(parsed, list) and len(parsed) >= 1:
                    structured = parsed[:num_questions]
                    # Basic validation/cleanup for MCQ
                    if qtype_lower == "mcq":
                        validated = []
                        for item in structured:
                            q = {
                                "question": str(item.get("question", "")).strip(),
                                "options": item.get("options") if isinstance(item.get("options"), list) else [],
                                "correct": item.get("correct", "")
                            }
                            # Ensure labels for options
                            if len(q["options"]) == 4:
                                validated.append(q)
                        if len(validated) >= num_questions:
                            self.structured_questions = validated[:num_questions]
                            self.questions = [s["question"] for s in self.structured_questions]
                            return self.questions
                    else:
                        # For other types, accept parsed questions if they have 'question'
                        validated = [ {"question": str(it.get("question", "")).strip(), **({k:v for k,v in it.items() if k!='question'} )} for it in structured if it.get("question") ]
                        if len(validated) >= num_questions:
                            self.structured_questions = validated[:num_questions]
                            self.questions = [s["question"] for s in self.structured_questions]
                            return self.questions
            except Exception:
                logging.debug("generate_questions: structured JSON parse failed", exc_info=True)

            # If structured parse fails, continue to free-form extraction below
        else:
            # No qtype requested: use the previous free-form prompt
            prompt = f"""
You are an interview question generator.
Generate exactly {num_questions} {level}-level interview questions based ONLY on the following document context.

Rules:
- No intro text.
- Each line = one valid question ending with a question mark (?).

Document Context:
{context}

Return only the list of questions, one per line.
"""
            result = gemini_generate(prompt)

        # Log raw output for debugging
        logging.info("generate_questions: gemini result length=%d", len(result) if isinstance(result, str) else 0)
        logging.debug("generate_questions: raw result:\n%s", result)

        # Attempt multiple extraction strategies to be robust against different response formats
        clean_qs: List[str] = []

        # 1) Extract numbered lines that end with a question mark, e.g. '1) What ...?'
        try:
            numbered = re.findall(r"(?m)^\s*\d+\s*[\).:-]*\s*(.+?\?)\s*$", result)
            if numbered:
                clean_qs.extend([q.strip() for q in numbered])
        except Exception:
            logging.debug("generate_questions: numbered extraction failed", exc_info=True)

        # 2) Extract any sentence that ends with a question mark
        try:
            ques = re.findall(r"([^\n\r?.!]+\?)", result)
            if ques:
                clean_qs.extend([q.strip() for q in ques if q.strip()])
        except Exception:
            logging.debug("generate_questions: question mark extraction failed", exc_info=True)

        # 3) Fallback: split lines and keep those that look like questions or start with question words
        if len(clean_qs) < num_questions:
            raw_lines = [line.strip(" -0123456789.)\t\u2022") for line in result.splitlines() if line.strip()]
            question_keywords = ("what", "why", "how", "when", "where", "name", "explain", "describe", "list", "define", "which", "who")
            for line in raw_lines:
                l = line.strip()
                if not l:
                    continue
                if l.endswith("?") or l.lower().startswith(question_keywords):
                    clean_qs.append(l)

        # Deduplicate while preserving order
        seen = set()
        deduped: List[str] = []
        for q in clean_qs:
            if q not in seen:
                deduped.append(q)
                seen.add(q)

        # If still not enough, create simple fallback questions from document chunks
        if len(deduped) < num_questions:
            logging.info("generate_questions: insufficient questions from Gemini (%d), creating fallback questions", len(deduped))
            for i, chunk in enumerate(self.chunks[:num_questions * 2]):
                if len(deduped) >= num_questions:
                    break
                snippet = chunk.split(".")[0][:120].strip()
                if not snippet:
                    continue
                fallback_q = f"Explain the following: {snippet}?"
                if fallback_q not in deduped:
                    deduped.append(fallback_q)

        self.questions = deduped[:num_questions]
        return self.questions

    # -------------------------
    # Answer Evaluation
    # -------------------------
    def evaluate_answers(self, user_answers: List[str]) -> Tuple[float, List[dict]]:
        """Evaluates answers using Gemini and returns average score + detailed feedback."""
        if not self.questions:
            raise ValueError("No questions have been generated.")
        if len(user_answers) != len(self.questions):
            raise ValueError("Number of answers must match number of questions.")

        total_score = 0
        feedback_list = []

        for q, a in zip(self.questions, user_answers):
            context = "\n\n".join(self.chunks[:5])
            prompt = f"""
You are an interviewer evaluating a candidate's response.

Question: {q}
Candidate Answer: {a}

Using the context below:
{context}

Evaluate the answer and give:
- score: integer from 0 to 10
- short feedback: 1-2 sentences explaining strengths/weaknesses
- correct_answer: the ideal or model answer (a concise phrase or sentence). For MCQs return the correct option letter and text (e.g. 'B) Option text').

Return JSON exactly (no extra text), for example:
{{"score": 7, "feedback": "Good explanation...", "correct_answer": "B) Option text"}}
"""
            eval_text = gemini_generate(prompt)

            try:
                data = json.loads(re.search(r'\{.*\}', eval_text, re.S).group())
            except Exception:
                logging.debug("evaluate_answers: failed to parse eval_text: %s", eval_text)
                data = {"score": 0, "feedback": "⚠ Could not parse Gemini response.", "correct_answer": ""}

            feedback_list.append({
                "question": q,
                "user_answer": a,
                "score": data.get("score", 0),
                "feedback": data.get("feedback", ""),
                "correct_answer": data.get("correct_answer", "")
            })
            total_score += data.get("score", 0)

        avg_score = round(total_score / len(self.questions), 2)
        self.feedback = feedback_list
        return avg_score, feedback_list

    # -------------------------
    # Cache Management
    # -------------------------
    def clear_cache(self):
        """Resets loaded data."""
        self.index = None
        self.chunks = None
        self.questions = []
        self.feedback = []
        return "🧹 Interview session cleared."


# -----------------------------
# ✅ Example usage (for backend)
# -----------------------------
# from smartinterview import InterviewCopilot
# bot = InterviewCopilot()
# bot.load_document("resume.pdf")
# qs = bot.generate_questions(num_questions=5, level="easy")
# avg, feedback = bot.evaluate_answers(["answer1", "answer2", ...])