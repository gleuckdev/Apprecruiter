import logging
import os
import json
from openai import OpenAI

logger = logging.getLogger(__name__)

def generate_candidate_persona(parsed_data):
    """
    Generate a candidate persona profile using OpenAI
    
    Args:
        parsed_data (dict): The parsed resume data
        
    Returns:
        dict: A persona object with ideal_roles, key_strengths, growth_areas, and team_fit
    """
    try:
        # Check if OpenAI API key is available
        api_key = os.environ.get('OPENAI_API_KEY')
        
        if not api_key:
            logger.warning("OpenAI API key not found - returning default persona")
            return {
                "ideal_roles": [],
                "key_strengths": [],
                "growth_areas": [],
                "team_fit": "Not analyzed"
            }
        
        client = OpenAI(api_key=api_key)
        
        # Format the input data
        skills = parsed_data.get('skills', [])
        experience = parsed_data.get('experience', [])
        education = parsed_data.get('education', [])
        summary = parsed_data.get('summary', '')
        
        # Format experience for the prompt
        experience_text = ""
        if isinstance(experience, list):
            for job in experience:
                if isinstance(job, dict):
                    title = job.get('title', '')
                    company = job.get('company', '')
                    years = job.get('years', '')
                    experience_text += f"{title} at {company} ({years})\n"
                else:
                    experience_text += f"{job}\n"
        else:
            experience_text = str(experience)
        
        # Format education for the prompt
        education_text = ""
        if isinstance(education, list):
            for edu in education:
                if isinstance(edu, dict):
                    degree = edu.get('degree', '')
                    school = edu.get('school', '')
                    year = edu.get('year', '')
                    education_text += f"{degree} from {school} ({year})\n"
                else:
                    education_text += f"{edu}\n"
        else:
            education_text = str(education)
        
        # Create the prompt
        prompt = f"""
        Based on the following resume information, create a candidate persona profile:
        
        Skills: {', '.join(skills) if isinstance(skills, list) else skills}
        
        Experience:
        {experience_text}
        
        Education:
        {education_text}
        
        Summary:
        {summary}
        
        Generate a structured JSON response with the following sections:
        1. ideal_roles: List of 3-5 job roles this candidate would be most suited for
        2. key_strengths: List of 3-5 key strengths based on their experience and skills
        3. growth_areas: List of 2-3 areas where the candidate could improve
        4. team_fit: A brief description of what kind of team culture they would thrive in
        
        Format your response as a valid JSON object without any additional text.
        """
        
        # Get the response from OpenAI 
        # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
        # do not change this unless explicitly requested by the user
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )
        
        # Parse the response
        result = json.loads(response.choices[0].message.content)
        
        # Return the persona
        return {
            "ideal_roles": result.get("ideal_roles", []),
            "key_strengths": result.get("key_strengths", []),
            "growth_areas": result.get("growth_areas", []),
            "team_fit": result.get("team_fit", "")
        }
        
    except Exception as e:
        logger.error(f"Error generating candidate persona: {str(e)}")
        return {
            "ideal_roles": [],
            "key_strengths": [],
            "growth_areas": [],
            "team_fit": f"Error during analysis: {str(e)}"
        }