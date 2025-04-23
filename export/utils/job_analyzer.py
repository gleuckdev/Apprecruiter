# utils/job_analyzer.py
import logging
import json
import openai

logger = logging.getLogger(__name__)

def analyze_job_description(description):
    """Use OpenAI to analyze job description and extract structured data"""
    try:
        # The newest OpenAI model is "gpt-4o" which was released May 13, 2024.
        # do not change this unless explicitly requested by the user
        analysis = openai.chat.completions.create(
            model="gpt-4o",
            messages=[{
                "role": "system",
                "content": """
                You are a job analyst. Analyze the job description and extract the following information:
                - title (string): Job title
                - location (string): Job location
                - experience (string): Experience requirement in years
                - required_skills (list): List of required skills
                - preferred_skills (list): List of preferred skills
                - education (string): Education requirements
                - job_type (string): Full-time, part-time, contract, etc.
                - salary_range (string): Salary range if mentioned
                - company (string): Company name if mentioned
                
                Return the data as a structured JSON object.
                """
            }, {
                "role": "user",
                "content": description
            }],
            response_format={"type": "json_object"}
        )
        
        job_details = json.loads(analysis.choices[0].message.content)
        return job_details
        
    except Exception as e:
        logger.error(f"Job analysis failed: {str(e)}")
        return {
            "title": "Untitled Position",
            "location": "Unknown",
            "experience": "Not specified",
            "required_skills": [],
            "preferred_skills": [],
            "education": "Not specified",
            "job_type": "Not specified",
            "salary_range": "Not specified",
            "company": "Unknown"
        }

def generate_embedding(description):
    """Generate embedding vector for the job description using OpenAI"""
    try:
        embedding_response = openai.embeddings.create(
            input=description,
            model="text-embedding-3-small"
        )
        
        return embedding_response.data[0].embedding
        
    except Exception as e:
        logger.error(f"Embedding generation failed: {str(e)}")
        return []

def generate_job_posting(job_details):
    """Create a formatted job posting from structured details"""
    posting = f"# {job_details.get('title', 'Position')}\n\n"
    
    if job_details.get('company'):
        posting += f"**Company:** {job_details['company']}\n\n"
        
    if job_details.get('location'):
        posting += f"**Location:** {job_details['location']}\n\n"
        
    if job_details.get('job_type'):
        posting += f"**Type:** {job_details['job_type']}\n\n"
        
    if job_details.get('salary_range') and job_details['salary_range'] != 'Not specified':
        posting += f"**Salary:** {job_details['salary_range']}\n\n"
        
    posting += "## Requirements\n\n"
    
    if job_details.get('experience') and job_details['experience'] != 'Not specified':
        posting += f"**Experience:** {job_details['experience']}\n\n"
        
    if job_details.get('education') and job_details['education'] != 'Not specified':
        posting += f"**Education:** {job_details['education']}\n\n"
        
    if job_details.get('required_skills') and len(job_details['required_skills']) > 0:
        posting += "**Required Skills:**\n"
        for skill in job_details['required_skills']:
            posting += f"- {skill}\n"
        posting += "\n"
        
    if job_details.get('preferred_skills') and len(job_details['preferred_skills']) > 0:
        posting += "**Preferred Skills:**\n"
        for skill in job_details['preferred_skills']:
            posting += f"- {skill}\n"
        posting += "\n"
        
    return posting
