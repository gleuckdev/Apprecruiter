# utils/resume_parser.py
import logging
from io import BytesIO
import json
import openai
from PIL import Image
import pytesseract

logger = logging.getLogger(__name__)

def extract_text_from_file(file_content, file_type):
    """Extract text from various file types"""
    text = ""
    
    try:
        if file_type in ['png', 'jpg', 'jpeg']:
            # Extract text from image using OCR
            img = Image.open(BytesIO(file_content))
            text = pytesseract.image_to_string(img)
        elif file_type == 'pdf':
            # For PDF, we'd normally use PyPDF2 or similar
            # Since we can't install additional packages, we'll return a placeholder
            text = "PDF content extraction requires additional libraries."
        elif file_type == 'docx':
            # For DOCX, we'd normally use python-docx
            # Since we can't install additional packages, we'll return a placeholder
            text = "DOCX content extraction requires additional libraries."
        else:
            # Assume it's text
            text = file_content.decode('utf-8', errors='ignore')
            
    except Exception as e:
        logger.error(f"Text extraction failed: {str(e)}")
        text = "Failed to extract text from file."
        
    return text

def analyze_resume(text):
    """Use OpenAI to analyze resume text and extract structured data"""
    try:
        # The newest OpenAI model is "gpt-4o" which was released May 13, 2024.
        # do not change this unless explicitly requested by the user
        analysis = openai.chat.completions.create(
            model="gpt-4o",
            messages=[{
                "role": "system",
                "content": """
                You are a resume parser. Extract the following information from the resume text and return it as JSON:
                - skills (list): Technical and soft skills mentioned in the resume
                - experience (list): List of jobs with company, title, years, and brief description
                - education (list): List of degrees with school, degree, field, year
                - summary (string): Brief overview of the candidate's background
                
                Format all text properly and ensure lists are well-structured. Return only the JSON object.
                """
            }, {
                "role": "user",
                "content": text
            }],
            response_format={"type": "json_object"}
        )
        
        resume_data = json.loads(analysis.choices[0].message.content)
        return resume_data
        
    except Exception as e:
        logger.error(f"Resume analysis failed: {str(e)}")
        return {
            "skills": [],
            "experience": [],
            "education": [],
            "summary": "Failed to analyze resume."
        }

def generate_embedding(text):
    """Generate embedding vector for the text using OpenAI"""
    try:
        embedding_response = openai.embeddings.create(
            input=text,
            model="text-embedding-3-small"
        )
        
        return embedding_response.data[0].embedding
        
    except Exception as e:
        logger.error(f"Embedding generation failed: {str(e)}")
        return []
