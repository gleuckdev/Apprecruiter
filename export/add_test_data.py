import os
import json
import sys
from datetime import datetime
import random

# Add direct database connection
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from models import Candidate, Job, JobCandidateMatch, CandidateRating, Recruiter

# Get database URL from environment
DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    print("Error: DATABASE_URL environment variable not set.")
    sys.exit(1)

# Create engine and session
engine = create_engine(DATABASE_URL)
Session = scoped_session(sessionmaker(bind=engine))
session = Session()

# Sample job data
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

# Sample candidate data with realistic information
sample_candidates = [
    {
        "name": "Alex Johnson",
        "email": "alex.johnson@example.com",
        "phone": "123-456-7890",
        "parsed_data": {
            "skills": ["Python", "Machine Learning", "Data Analysis", "SQL", "TensorFlow", "PyTorch", "Scikit-learn"],
            "experience": [
                {
                    "title": "Senior Data Scientist",
                    "company": "TechCorp Analytics",
                    "years": "2020-2023",
                    "description": "Led machine learning projects for Fortune 500 clients, improving prediction accuracy by 35%"
                },
                {
                    "title": "Data Scientist",
                    "company": "DataInsights Inc",
                    "years": "2017-2020",
                    "description": "Developed customer segmentation models increasing marketing ROI by 28%"
                }
            ],
            "education": [
                {
                    "degree": "M.S. Computer Science",
                    "institution": "Stanford University",
                    "years": "2015-2017",
                    "field": "Machine Learning"
                },
                {
                    "degree": "B.S. Mathematics",
                    "institution": "UCLA",
                    "years": "2011-2015",
                    "field": "Applied Mathematics"
                }
            ],
            "summary": "Experienced data scientist with expertise in machine learning and predictive modeling. Proven track record of delivering impactful solutions across multiple industries."
        },
        "persona": {
            "ideal_roles": ["Data Scientist", "ML Engineer", "AI Researcher"],
            "key_strengths": ["Algorithm development", "Statistical analysis", "Problem-solving", "Technical leadership"],
            "growth_areas": ["Cloud infrastructure", "Big data technologies"],
            "team_fit": "Works well in collaborative research environments. Communicates technical concepts clearly to non-technical stakeholders."
        },
        "match_score": 0.85
    },
    {
        "name": "Sophia Liu",
        "email": "sophia.liu@example.com",
        "phone": "234-567-8901",
        "parsed_data": {
            "skills": ["JavaScript", "React", "Node.js", "GraphQL", "TypeScript", "Redux", "AWS", "Docker"],
            "experience": [
                {
                    "title": "Senior Frontend Developer",
                    "company": "WebSolutions Ltd",
                    "years": "2019-2023",
                    "description": "Architected and implemented scalable frontend solutions for enterprise clients"
                },
                {
                    "title": "Frontend Developer",
                    "company": "TechStartup Co",
                    "years": "2016-2019",
                    "description": "Built responsive web applications and contributed to open-source projects"
                }
            ],
            "education": [
                {
                    "degree": "B.S. Computer Science",
                    "institution": "University of Washington",
                    "years": "2012-2016",
                    "field": "Web Development"
                }
            ],
            "summary": "Frontend specialist with full-stack capabilities and a focus on creating elegant, efficient user experiences. Passionate about modern JavaScript frameworks and performance optimization."
        },
        "persona": {
            "ideal_roles": ["Frontend Developer", "UI Engineer", "Full Stack Developer"],
            "key_strengths": ["User interface design", "Performance optimization", "Component architecture"],
            "growth_areas": ["Backend technologies", "System design"],
            "team_fit": "Thrives in agile environments with a focus on user-centered design practices."
        },
        "match_score": 0.72
    },
    {
        "name": "Marcus Williams",
        "email": "marcus.williams@example.com",
        "phone": "345-678-9012",
        "parsed_data": {
            "skills": ["Project Management", "Agile", "Scrum", "JIRA", "Stakeholder Management", "Risk Management", "Budgeting"],
            "experience": [
                {
                    "title": "Project Manager",
                    "company": "Enterprise Solutions Group",
                    "years": "2018-2023",
                    "description": "Managed cross-functional teams to deliver complex technology projects"
                },
                {
                    "title": "Assistant Project Manager",
                    "company": "Digital Transformations Inc",
                    "years": "2015-2018",
                    "description": "Supported project planning and execution for digital transformation initiatives"
                }
            ],
            "education": [
                {
                    "degree": "MBA",
                    "institution": "Michigan State University",
                    "years": "2013-2015",
                    "field": "Business Administration"
                },
                {
                    "degree": "B.A. Business",
                    "institution": "University of Illinois",
                    "years": "2009-2013",
                    "field": "Business Management"
                }
            ],
            "summary": "Certified project manager with expertise in agile methodologies and a track record of delivering complex projects on time and under budget."
        },
        "persona": {
            "ideal_roles": ["Project Manager", "Program Manager", "Scrum Master"],
            "key_strengths": ["Team leadership", "Stakeholder management", "Strategic planning"],
            "growth_areas": ["Technical knowledge", "Data-driven decision making"],
            "team_fit": "Natural leader who excels at aligning diverse teams around common goals."
        },
        "match_score": 0.65
    },
    {
        "name": "Emily Chen",
        "email": "emily.chen@example.com",
        "phone": "456-789-0123",
        "parsed_data": {
            "skills": ["UI/UX Design", "Figma", "Adobe XD", "Sketch", "User Research", "Prototyping", "Wireframing", "Design Systems"],
            "experience": [
                {
                    "title": "Senior UX Designer",
                    "company": "Creative Design Agency",
                    "years": "2020-2023",
                    "description": "Led user experience design for major e-commerce and fintech clients"
                },
                {
                    "title": "UI Designer",
                    "company": "Digital Products Inc",
                    "years": "2017-2020",
                    "description": "Created user interfaces for mobile and web applications"
                }
            ],
            "education": [
                {
                    "degree": "M.A. Design",
                    "institution": "Rhode Island School of Design",
                    "years": "2015-2017",
                    "field": "Interaction Design"
                },
                {
                    "degree": "B.F.A.",
                    "institution": "Parsons School of Design",
                    "years": "2011-2015",
                    "field": "Visual Design"
                }
            ],
            "summary": "User experience designer with a passion for creating intuitive, accessible digital products. Combines creative thinking with user research to solve complex design challenges."
        },
        "persona": {
            "ideal_roles": ["UX Designer", "Product Designer", "UI Designer"],
            "key_strengths": ["User-centered design", "Visual communication", "Design thinking"],
            "growth_areas": ["Frontend development", "Data visualization"],
            "team_fit": "Collaborative designer who bridges the gap between user needs and technical constraints."
        },
        "match_score": 0.78
    },
    {
        "name": "Robert Taylor",
        "email": "robert.taylor@example.com",
        "phone": "567-890-1234",
        "parsed_data": {
            "skills": ["DevOps", "Kubernetes", "Docker", "CI/CD", "AWS", "Terraform", "Jenkins", "Monitoring", "Ansible"],
            "experience": [
                {
                    "title": "DevOps Engineer",
                    "company": "Cloud Services Ltd",
                    "years": "2019-2023",
                    "description": "Implemented CI/CD pipelines and managed cloud infrastructure for enterprise applications"
                },
                {
                    "title": "Systems Administrator",
                    "company": "Tech Infrastructure Co",
                    "years": "2016-2019",
                    "description": "Maintained and optimized server environments and deployment processes"
                }
            ],
            "education": [
                {
                    "degree": "B.S. Computer Science",
                    "institution": "Georgia Tech",
                    "years": "2012-2016",
                    "field": "Systems Administration"
                }
            ],
            "summary": "DevOps engineer focused on building reliable, scalable infrastructure and streamlining deployment processes. Expert in containerization and cloud technologies."
        },
        "persona": {
            "ideal_roles": ["DevOps Engineer", "Site Reliability Engineer", "Cloud Architect"],
            "key_strengths": ["Automation", "Infrastructure as code", "System reliability"],
            "growth_areas": ["Security practices", "Cost optimization"],
            "team_fit": "Methodical problem-solver who thrives in environments that value continuous improvement."
        },
        "match_score": 0.71
    },
    {
        "name": "Sarah Miller",
        "email": "sarah.miller@example.com",
        "phone": "678-901-2345",
        "parsed_data": {
            "skills": ["Marketing Strategy", "SEO", "Content Marketing", "Social Media Marketing", "Analytics", "Email Campaigns", "Google Ads", "A/B Testing"],
            "experience": [
                {
                    "title": "Digital Marketing Manager",
                    "company": "Growth Marketing Agency",
                    "years": "2018-2023",
                    "description": "Led digital marketing strategies for B2B and B2C clients across multiple industries"
                },
                {
                    "title": "Marketing Specialist",
                    "company": "E-commerce Solutions Inc",
                    "years": "2015-2018",
                    "description": "Managed SEO and content marketing initiatives resulting in 45% traffic growth"
                }
            ],
            "education": [
                {
                    "degree": "M.S. Marketing",
                    "institution": "Northwestern University",
                    "years": "2013-2015",
                    "field": "Digital Marketing"
                },
                {
                    "degree": "B.A. Communications",
                    "institution": "University of Oregon",
                    "years": "2009-2013",
                    "field": "Marketing"
                }
            ],
            "summary": "Results-driven digital marketer with expertise in developing integrated marketing strategies that drive growth and engagement across multiple channels."
        },
        "persona": {
            "ideal_roles": ["Marketing Manager", "Digital Marketing Specialist", "Growth Marketer"],
            "key_strengths": ["Data-driven marketing", "Content strategy", "Campaign management"],
            "growth_areas": ["Technical marketing", "Marketing automation"],
            "team_fit": "Strategic thinker who balances creative and analytical approaches to marketing challenges."
        },
        "match_score": 0.58
    },
    {
        "name": "David Kim",
        "email": "david.kim@example.com",
        "phone": "789-012-3456",
        "parsed_data": {
            "skills": ["Product Management", "User Stories", "Roadmapping", "Agile", "Market Research", "A/B Testing", "Data Analysis", "Stakeholder Management"],
            "experience": [
                {
                    "title": "Senior Product Manager",
                    "company": "Tech Innovations Ltd",
                    "years": "2020-2023",
                    "description": "Led product strategy and development for enterprise SaaS platform"
                },
                {
                    "title": "Product Manager",
                    "company": "Digital Solutions Inc",
                    "years": "2017-2020",
                    "description": "Managed product lifecycle from conception to launch for consumer applications"
                }
            ],
            "education": [
                {
                    "degree": "MBA",
                    "institution": "UC Berkeley",
                    "years": "2015-2017",
                    "field": "Product Management"
                },
                {
                    "degree": "B.S. Information Systems",
                    "institution": "Carnegie Mellon University",
                    "years": "2011-2015",
                    "field": "Business Technology"
                }
            ],
            "summary": "Customer-focused product manager with a blend of technical knowledge and business acumen. Experienced in leading cross-functional teams to deliver successful products."
        },
        "persona": {
            "ideal_roles": ["Product Manager", "Product Owner", "Program Manager"],
            "key_strengths": ["Product strategy", "User-focused development", "Cross-functional leadership"],
            "growth_areas": ["Technical depth", "Data science applications"],
            "team_fit": "Collaborative leader who excels at translating user needs into actionable product requirements."
        },
        "match_score": 0.68
    },
    {
        "name": "Jessica Rodriguez",
        "email": "jessica.rodriguez@example.com",
        "phone": "890-123-4567",
        "parsed_data": {
            "skills": ["Java", "Spring Boot", "Microservices", "SQL", "MongoDB", "AWS", "Docker", "RESTful APIs", "JUnit"],
            "experience": [
                {
                    "title": "Backend Developer",
                    "company": "Enterprise Software Solutions",
                    "years": "2019-2023",
                    "description": "Designed and implemented scalable microservices architecture"
                },
                {
                    "title": "Java Developer",
                    "company": "Financial Systems Inc",
                    "years": "2016-2019",
                    "description": "Developed backend services for financial transaction processing systems"
                }
            ],
            "education": [
                {
                    "degree": "M.S. Computer Engineering",
                    "institution": "University of Texas",
                    "years": "2014-2016",
                    "field": "Software Engineering"
                },
                {
                    "degree": "B.S. Computer Science",
                    "institution": "University of Arizona",
                    "years": "2010-2014",
                    "field": "Software Development"
                }
            ],
            "summary": "Backend developer specializing in Java and microservices architecture. Passionate about building robust, scalable systems with a focus on performance and reliability."
        },
        "persona": {
            "ideal_roles": ["Backend Developer", "Java Developer", "Software Engineer"],
            "key_strengths": ["System architecture", "API design", "Database optimization"],
            "growth_areas": ["Frontend technologies", "Cloud-native development"],
            "team_fit": "Detail-oriented developer who values clean code and extensive testing."
        },
        "match_score": 0.81
    }
]

def add_test_data():
    try:
        # Get admin user for uploading candidates
        admin_user = session.query(Recruiter).filter_by(role='admin').first()
        
        if not admin_user:
            print("No admin user found. Creating admin user...")
            # Create admin user if it doesn't exist
            admin_user = Recruiter(
                name="Admin User",
                email="admin@example.com",
                password_hash="$2b$12$5iVo7QJ2Bs7bXwQP5Ue12uX3z0WNjkIFy/E/2M5dQN3IFNx/ZzVn6",  # This is a hash for "password123"
                role="admin",
                role_id="admin",
                created_at=datetime.utcnow()
            )
            session.add(admin_user)
            session.commit()
            print(f"Created admin user: {admin_user.id}")
        
        print(f"Using admin user: {admin_user.name} (ID: {admin_user.id})")
        
        # Add sample job if no jobs exist
        existing_job = session.query(Job).filter_by(title=sample_job['title'], company=sample_job['company']).first()
        job = None
        
        if not existing_job:
            print(f"Creating sample job: {sample_job['title']}...")
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
            session.add(job)
            session.commit()
            print(f"Created job: {job.id} - {job.title}")
        else:
            job = existing_job
            print(f"Using existing job: {job.id} - {job.title}")
        
        # Add sample candidates
        for candidate_data in sample_candidates:
            print(f"Processing candidate: {candidate_data['name']}")
            
            # Check if candidate already exists
            existing = session.query(Candidate).filter_by(email=candidate_data['email']).first()
            if existing:
                print(f"  Candidate {candidate_data['name']} already exists. Skipping.")
                continue
                
            # Create candidate
            candidate = Candidate(
                name=candidate_data['name'],
                email=candidate_data['email'],
                phone=candidate_data['phone'],
                resume_file=f"sample_{candidate_data['name'].lower().replace(' ', '_')}.pdf",
                gcs_url=f"/static/uploads/sample_{candidate_data['name'].lower().replace(' ', '_')}.pdf",
                parsed_data=candidate_data['parsed_data'],
                persona=candidate_data['persona'],
                embedding=[0.0] * 1536,  # Default embedding
                uploaded_by=admin_user.id,
                created_at=datetime.utcnow()
            )
            
            # Add to database
            session.add(candidate)
            session.commit()
            print(f"  Created candidate: {candidate.id}")
            
            # Create match with job
            if job:
                match_score = round(candidate_data['match_score'] * (0.8 + (random.randint(0, 40) / 100.0)), 2)  # Varies score slightly
                match_score = max(0.3, min(0.95, match_score))  # Keep between 0.3 and 0.95
                
                match = JobCandidateMatch(
                    job_id=job.id,
                    candidate_id=candidate.id,
                    score=match_score,
                    created_at=datetime.utcnow()
                )
                session.add(match)
                print(f"  Created match with job {job.id}: {job.title} - Score: {match_score:.2f}")
            
            # Create candidate rating
            rating = CandidateRating(
                candidate_id=candidate.id,
                recruiter_id=admin_user.id,
                score=round(candidate_data['match_score'] * 0.9, 2),  # Slightly lower than AI score
                notes=f"Initial evaluation of {candidate_data['name']}'s profile shows strong potential.",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            session.add(rating)
            print(f"  Created rating: {rating.score}")
            
            session.commit()
            print(f"  Candidate {candidate_data['name']} added successfully!")
            
        print("\nAll sample data added successfully!")
        
    except Exception as e:
        print(f"Error adding sample data: {str(e)}")
        session.rollback()
        raise
    finally:
        session.close()

if __name__ == "__main__":
    add_test_data()