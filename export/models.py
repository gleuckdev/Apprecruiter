# models.py
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class Role(db.Model):
    """
    Role model for storing role-based access control information.
    """
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.String(50), unique=True, nullable=False)  # e.g., 'admin', 'recruiter'
    name = db.Column(db.String(100), nullable=False)  # e.g., 'Administrator', 'Recruiter'
    permissions = db.Column(db.JSON, nullable=False, default=list)  # List of permission strings
    inherits = db.Column(db.String(50), nullable=True)  # Parent role ID if any
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def get_all_permissions(self):
        """
        Get all permissions for this role, including inherited ones
        
        Returns:
            list: Combined list of permissions
        """
        # Start with own permissions
        all_permissions = list(self.permissions or [])
        
        # Add inherited permissions if applicable
        if self.inherits:
            parent_role = Role.query.filter_by(role_id=self.inherits).first()
            if parent_role:
                parent_permissions = parent_role.get_all_permissions()
                # Add parent permissions without duplicates
                all_permissions.extend([p for p in parent_permissions if p not in all_permissions])
        
        return all_permissions

class Recruiter(db.Model):
    __tablename__ = 'recruiters'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    # Role fields
    role = db.Column(db.String(20), default='recruiter')  # 'recruiter' or 'admin'
    role_id = db.Column(db.String(50), db.ForeignKey('roles.role_id'), default='recruiter')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    jobs = db.relationship('Job', backref='recruiter', lazy=True)
    ratings = db.relationship('CandidateRating', backref='recruiter', lazy=True)
    candidates = db.relationship('Candidate', foreign_keys='Candidate.uploaded_by', backref='uploaded_by_recruiter', lazy=True)
    # Relationship to Role model
    assigned_role = db.relationship('Role', foreign_keys=[role_id], backref='recruiters', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def is_admin(self):
        # Check both legacy and new role systems
        return self.role == 'admin' or self.role_id == 'admin'
    
    def has_permission(self, permission):
        """
        Check if the recruiter has a specific permission
        
        Args:
            permission: The permission string to check
            
        Returns:
            bool: True if the permission is granted, False otherwise
        """
        # Admins have all permissions
        if self.is_admin():
            return True
        
        # Check role-based permissions
        if self.assigned_role:
            all_permissions = self.assigned_role.get_all_permissions()
            return permission in all_permissions
        
        # Fallback for legacy system - basic permissions for regular recruiters
        recruiter_permissions = [
            'candidates:view', 'candidates:add',
            'notes:create', 'notes:view', 'notes:edit', 'notes:delete',
            'jobs:list', 'jobs:view'
        ]
        
        return permission in recruiter_permissions
        
    def can_access_job(self, job):
        """
        Check if the recruiter can access a specific job
        
        Args:
            job: The Job object to check access for
            
        Returns:
            bool: True if the recruiter can access the job, False otherwise
        """
        # Admin can access all jobs
        if self.has_permission('jobs:view_all'):
            return True
            
        # Owner can access their own jobs
        if job.recruiter_id == self.id:
            return True
            
        # Check if the job's owner has shared jobs with this recruiter
        sharing = RecruiterSharing.query.filter_by(
            owner_id=job.recruiter_id,
            shared_with_id=self.id,
            share_jobs=True
        ).first()
        
        return sharing is not None
        
    def can_access_candidate(self, candidate):
        """
        Check if the recruiter can access a specific candidate
        
        Args:
            candidate: The Candidate object to check access for
            
        Returns:
            bool: True if the recruiter can access the candidate, False otherwise
        """
        # Admin can access all candidates
        if self.has_permission('candidates:view_all'):
            return True
            
        # Owner can access their own uploaded candidates
        if candidate.uploaded_by == self.id:
            return True
            
        # Check if the candidate's uploader has shared candidates with this recruiter
        if candidate.uploaded_by:
            sharing = RecruiterSharing.query.filter_by(
                owner_id=candidate.uploaded_by,
                shared_with_id=self.id,
                share_candidates=True
            ).first()
            
            if sharing is not None:
                return True
                
        return False

class Job(db.Model):
    __tablename__ = 'jobs'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100))
    experience = db.Column(db.String(50))
    education = db.Column(db.String(100))
    job_type = db.Column(db.String(50))
    salary_range = db.Column(db.String(100))
    company = db.Column(db.String(100))
    required_skills = db.Column(db.JSON)
    preferred_skills = db.Column(db.JSON)
    embedding = db.Column(db.JSON)
    recruiter_id = db.Column(db.Integer, db.ForeignKey('recruiters.id'), nullable=False)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    matches = db.relationship('JobCandidateMatch', backref='job', lazy=True)

class Candidate(db.Model):
    __tablename__ = 'candidates'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    resume_file = db.Column(db.String(255))
    gcs_url = db.Column(db.String(255))
    parsed_data = db.Column(db.JSON)
    embedding = db.Column(db.JSON)
    persona = db.Column(db.JSON)  # Stores candidate persona data
    uploaded_by = db.Column(db.Integer, db.ForeignKey('recruiters.id'))
    job_id = db.Column(db.Integer, db.ForeignKey('jobs.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    matches = db.relationship('JobCandidateMatch', backref='candidate', lazy=True)
    ratings = db.relationship('CandidateRating', backref='candidate', lazy=True)

class JobCandidateMatch(db.Model):
    __tablename__ = 'job_candidate_matches'
    
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('jobs.id'), nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidates.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
class Session(db.Model):
    __tablename__ = 'sessions'
    
    id = db.Column(db.String(32), primary_key=True)
    recruiter_id = db.Column(db.Integer, db.ForeignKey('recruiters.id'), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
class Invitation(db.Model):
    __tablename__ = 'invitations'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    role = db.Column(db.String(20), default='recruiter')  # Legacy field
    role_id = db.Column(db.String(50), db.ForeignKey('roles.role_id'), default='recruiter')
    used = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.Integer, db.ForeignKey('recruiters.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    # Data sharing options
    share_jobs = db.Column(db.Boolean, default=False)  # Share job listings with invitee
    share_candidates = db.Column(db.Boolean, default=False)  # Share candidates with invitee
    
    # Relationship to Role model
    assigned_role = db.relationship('Role', foreign_keys=[role_id], lazy=True)
    
class RecruiterSharing(db.Model):
    """
    Model to track data sharing relationships between recruiters
    """
    __tablename__ = 'recruiter_sharing'
    
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('recruiters.id'), nullable=False)
    shared_with_id = db.Column(db.Integer, db.ForeignKey('recruiters.id'), nullable=False)
    share_jobs = db.Column(db.Boolean, default=False)  # Share job listings
    share_candidates = db.Column(db.Boolean, default=False)  # Share candidates
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Define relationship constraints
    __table_args__ = (
        db.UniqueConstraint('owner_id', 'shared_with_id', name='uq_recruiter_sharing'),
    )
    
    # Relationships
    owner = db.relationship('Recruiter', foreign_keys=[owner_id], backref=db.backref('shared_with', lazy='dynamic'))
    shared_with = db.relationship('Recruiter', foreign_keys=[shared_with_id], backref=db.backref('shared_by', lazy='dynamic'))


class CandidateRating(db.Model):
    __tablename__ = 'candidate_ratings'
    
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidates.id'), nullable=False)
    recruiter_id = db.Column(db.Integer, db.ForeignKey('recruiters.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)  # 0-1 rating scale (aligned with OpenAI scores)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)