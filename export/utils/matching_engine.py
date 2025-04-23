# utils/matching_engine.py
import logging
import math

logger = logging.getLogger(__name__)

def calculate_embedding_similarity(embedding1, embedding2):
    """Calculate cosine similarity between two embeddings"""
    try:
        # Ensure embeddings have values
        if not embedding1 or not embedding2:
            return 0.0
            
        # Calculate dot product
        dot_product = sum(a * b for a, b in zip(embedding1, embedding2))
        
        # Calculate magnitudes
        magnitude1 = math.sqrt(sum(a * a for a in embedding1))
        magnitude2 = math.sqrt(sum(b * b for b in embedding2))
        
        # Calculate cosine similarity
        if magnitude1 > 0 and magnitude2 > 0:
            return dot_product / (magnitude1 * magnitude2)
        else:
            return 0.0
            
    except Exception as e:
        logger.error(f"Embedding similarity calculation failed: {str(e)}")
        return 0.0

def calculate_skills_match(candidate_skills, required_skills, preferred_skills):
    """Calculate skills match score between candidate and job"""
    try:
        # Normalize skills to lowercase for comparison
        candidate_skills_norm = set(s.lower() for s in candidate_skills)
        required_skills_norm = set(s.lower() for s in required_skills)
        preferred_skills_norm = set(s.lower() for s in preferred_skills)
        
        # Handle empty skills lists
        if not required_skills_norm and not preferred_skills_norm:
            return 0.5  # Neutral score if job doesn't specify skills
            
        # Calculate match percentages
        if required_skills_norm:
            required_match = len(candidate_skills_norm.intersection(required_skills_norm)) / len(required_skills_norm)
        else:
            required_match = 1.0  # Full match if no required skills
            
        if preferred_skills_norm:
            preferred_match = len(candidate_skills_norm.intersection(preferred_skills_norm)) / len(preferred_skills_norm)
        else:
            preferred_match = 0.5  # Neutral score if no preferred skills
            
        # Weight required skills higher than preferred
        weighted_score = (required_match * 0.7) + (preferred_match * 0.3)
        return weighted_score
        
    except Exception as e:
        logger.error(f"Skills match calculation failed: {str(e)}")
        return 0.0

def calculate_match_score(candidate, job):
    """Calculate overall match score between candidate and job"""
    try:
        # Get embedding similarity
        embedding_similarity = calculate_embedding_similarity(candidate.get('embedding', []), job.get('embedding', []))
        
        # Get skills match
        candidate_skills = candidate.get('parsed_data', {}).get('skills', [])
        required_skills = job.get('details', {}).get('required_skills', [])
        preferred_skills = job.get('details', {}).get('preferred_skills', [])
        skills_match = calculate_skills_match(candidate_skills, required_skills, preferred_skills)
        
        # Calculate combined score (60% embedding, 40% skills)
        combined_score = (embedding_similarity * 0.6) + (skills_match * 0.4)
        
        # Normalize to 0-1 range
        normalized_score = max(0.0, min(1.0, combined_score))
        return normalized_score
        
    except Exception as e:
        logger.error(f"Match score calculation failed: {str(e)}")
        return 0.0

def get_top_matches(candidates, job, limit=10, threshold=0.2):
    """Get top matching candidates for a job"""
    matches = []
    
    for candidate in candidates:
        score = calculate_match_score(candidate, job)
        if score >= threshold:
            matches.append({
                'candidate_id': candidate.get('id'),
                'name': candidate.get('name', 'Anonymous'),
                'email': candidate.get('email', ''),
                'phone': candidate.get('phone', ''),
                'score': score,
                'skills': candidate.get('parsed_data', {}).get('skills', []),
                'experience': candidate.get('parsed_data', {}).get('experience', []),
                'resume_url': candidate.get('gcs_url', '')
            })
    
    # Sort by score
    matches.sort(key=lambda x: x['score'], reverse=True)
    
    # Limit results
    return matches[:limit]
