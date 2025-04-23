"""
Role-based permission system for AI Recruiter.

This module provides utilities for managing roles and permissions throughout the application.
"""
from functools import wraps
from flask import abort, g, current_app
from models import Recruiter, Role

# Definition of available permissions
PERMISSIONS = {
    # User management
    'users:create': 'Create new users/recruiters',
    'users:view': 'View user/recruiter details',
    'users:edit': 'Edit user/recruiter details',
    'users:delete': 'Delete users/recruiters',
    'users:invite': 'Send invitations to new users',
    'users:admin': 'Create admin-level users and perform admin operations',
    
    # Job management
    'jobs:create': 'Create new job listings',
    'jobs:view': 'View job listings',
    'jobs:view_all': 'View all job listings in the system',
    'jobs:edit': 'Edit job listings',
    'jobs:delete': 'Delete job listings',
    'jobs:list': 'List all jobs',
    'jobs:approve': 'Approve job listings',
    
    # Candidate management
    'candidates:view': 'View candidate profiles',
    'candidates:view_all': 'View all candidate profiles in the system',
    'candidates:add': 'Add new candidates',
    'candidates:bulk_add': 'Bulk upload resumes',
    'candidates:edit': 'Edit candidate information',
    'candidates:delete': 'Delete candidates',
    'candidates:rate': 'Rate candidates',
    'candidates:generate_persona': 'Generate candidate personas',
    
    # Match management
    'matches:refresh': 'Refresh job-candidate matches',
    
    # Note management
    'notes:create': 'Create notes',
    'notes:view': 'View notes',
    'notes:edit': 'Edit own notes',
    'notes:delete': 'Delete own notes',
    'notes:delete_any': 'Delete any notes',
    
    # System
    'audits:view': 'View audit logs',
    'settings:edit': 'Edit system settings',
}

# Default role definitions
DEFAULT_ROLES = {
    'admin': {
        'name': 'Administrator',
        'permissions': [
            'users:create', 'users:view', 'users:edit', 'users:delete', 'users:invite', 'users:admin',
            'jobs:create', 'jobs:view', 'jobs:view_all', 'jobs:edit', 'jobs:delete', 'jobs:list', 'jobs:approve',
            'candidates:view', 'candidates:view_all', 'candidates:add', 'candidates:bulk_add', 'candidates:edit', 
            'candidates:delete', 'candidates:rate', 'candidates:generate_persona',
            'matches:refresh',
            'notes:create', 'notes:view', 'notes:edit', 'notes:delete', 'notes:delete_any',
            'audits:view', 'settings:edit'
        ],
        'inherits': None
    },
    'senior_recruiter': {
        'name': 'Senior Recruiter',
        'permissions': [
            'jobs:create', 'jobs:view', 'jobs:edit', 'jobs:delete', 'jobs:list',
            'candidates:bulk_add', 'candidates:rate', 'candidates:generate_persona',
            'matches:refresh',
            'notes:delete_any',
            'users:invite'
        ],
        'inherits': 'recruiter'
    },
    'recruiter': {
        'name': 'Recruiter',
        'permissions': [
            'candidates:view', 'candidates:add', 'candidates:rate',
            'notes:create', 'notes:view', 'notes:edit', 'notes:delete',
            'jobs:list', 'jobs:view'
        ],
        'inherits': None
    }
}

def requires_permission(permission):
    """
    Decorator for route handlers that checks if the current user has the required permission.
    
    Args:
        permission: The permission string to check
        
    Returns:
        Decorated function that will abort with 403 if permission is not granted
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Get the current user from the request context (assuming set by auth middleware)
            recruiter = g.get('current_user')
            
            if not recruiter:
                abort(401)  # Unauthorized if no user
                
            if not recruiter.has_permission(permission):
                current_app.logger.warning(f"Permission denied: {recruiter.email} attempted to access {permission}")
                abort(403)  # Forbidden if no permission
                
            return f(*args, **kwargs)
        return wrapped
    return decorator

def initialize_roles(db_session):
    """
    Initialize the default roles in the database if they don't exist.
    This should be called during application setup.
    
    Args:
        db_session: SQLAlchemy database session
    """
    for role_id, role_config in DEFAULT_ROLES.items():
        # Check if role exists
        role = db_session.query(Role).filter_by(role_id=role_id).first()
        
        if not role:
            # Create new role
            role = Role(
                role_id=role_id,
                name=role_config['name'],
                permissions=role_config['permissions'],
                inherits=role_config['inherits']
            )
            db_session.add(role)
            current_app.logger.info(f"Created role: {role_id}")
        else:
            # Update existing role with any new permissions
            # Get current permissions
            current_permissions = set(role.permissions)
            # Get default permissions for this role
            default_permissions = set(role_config['permissions'])
            
            # Find permissions to add (in default but not in current)
            permissions_to_add = default_permissions - current_permissions
            
            if permissions_to_add:
                # Add the new permissions to the existing ones
                role.permissions = list(current_permissions.union(permissions_to_add))
                current_app.logger.info(f"Updated role {role_id} with new permissions: {permissions_to_add}")
    
    # Commit the changes
    db_session.commit()
    current_app.logger.info("Roles initialized successfully")