import os
import sys
import json
from datetime import datetime
from flask import Flask
from models import db, Job, Recruiter
from main import app as application

# Sample job data with realistic information
sample_job = {
    "title": "Senior Software Engineer",
    "description": """
We are seeking an experienced Senior Software Engineer to join our dynamic development team. The ideal candidate will be responsible for designing, developing, and maintaining high-quality software solutions that meet our clients' needs.

Responsibilities:
- Develop high-quality software design and architecture
- Debug, test, and deploy software applications
- Develop technical documentation to define application requirements
- Lead code reviews and mentor junior team members
- Collaborate with cross-functional teams to define and implement innovative solutions

Requirements:
- Bachelor's degree in Computer Science, Engineering or related field
- 5+ years of software development experience
- Strong proficiency in one or more programming languages (Python, Java, JavaScript, etc.)
- Experience with databases and cloud technologies
- Excellent problem-solving and communication skills
    """,
    "location": "San Francisco, CA (Remote Friendly)",
    "experience": "5+ years",
    "education": "Bachelor's degree",
    "job_type": "Full-time",
    "salary_range": "$120,000 - $160,000",
    "company": "TechInnovate Solutions",
    "required_skills": ["Python", "Java", "JavaScript", "SQL", "Cloud Technologies", "Software Design"],
    "preferred_skills": ["Microservices", "Docker", "Kubernetes", "React", "AWS", "CI/CD"]
}

def add_sample_job():
    """Add a sample job to the database"""
    with application.app_context():
        # Get admin user for creating the job
        admin_user = Recruiter.query.filter_by(role='admin').first()
        
        if not admin_user:
            print("No admin user found. Please create an admin user first.")
            return
        
        print(f"Using admin user: {admin_user.name} (ID: {admin_user.id})")
        
        # Check if job already exists
        existing = Job.query.filter_by(title=sample_job['title'], company=sample_job['company']).first()
        if existing:
            print(f"Job '{sample_job['title']}' already exists. Skipping.")
            return
            
        # Create job
        job = Job(
            title=sample_job['title'],
            description=sample_job['description'],
            location=sample_job['location'],
            experience=sample_job['experience'],
            education=sample_job['education'],
            job_type=sample_job['job_type'],
            salary_range=sample_job['salary_range'],
            company=sample_job['company'],
            required_skills=sample_job['required_skills'],
            preferred_skills=sample_job['preferred_skills'],
            embedding=[0.0] * 1536,  # Default embedding
            recruiter_id=admin_user.id,
            status='active',
            created_at=datetime.utcnow()
        )
        
        # Add to database
        db.session.add(job)
        db.session.commit()
        print(f"Created job: {job.id} - {job.title}")
        print("Sample job added successfully!")

if __name__ == "__main__":
    add_sample_job()