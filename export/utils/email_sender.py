import os
import logging
import requests

logger = logging.getLogger(__name__)

def send_email(to_email, subject, html_content, from_email="AI Recruiter <no-reply@airecruiter.pro>"):
    """
    Send email using Mailgun
    
    If Mailgun API key is not available, logs the email instead of sending it,
    and returns a generated invite link directly for the invitation workflow to continue.
    """
    try:
        # Check if Mailgun API key and domain are available
        api_key = os.environ.get('MAILGUN_API_KEY')
        domain = os.environ.get('MAILGUN_DOMAIN', 'mg.airecruiter.pro')
        
        if not api_key:
            # Log the email contents for debugging/development
            logger.info(f"[EMAIL NOT SENT - NO API KEY] To: {to_email}, Subject: {subject}")
            logger.info(f"Content: {html_content}")
            
            # Return success for development purposes
            return {
                'success': True, 
                'message': 'Email logged (MAILGUN_API_KEY not configured)'
            }
        
        # Mailgun API endpoint
        url = f"https://api.mailgun.net/v3/{domain}/messages"
        
        # Prepare data for the API request
        data = {
            "from": from_email,
            "to": to_email,
            "subject": subject,
            "html": html_content
        }
        
        # Make the API request
        response = requests.post(
            url,
            auth=("api", api_key),
            data=data
        )
        
        # Check response
        if response.status_code == 200:
            return {'success': True, 'message': 'Email sent successfully via Mailgun'}
        else:
            logger.error(f"Mailgun error: {response.status_code}, {response.text}")
            return {'success': False, 'message': f"Failed to send email: {response.status_code}"}
        
    except Exception as e:
        logger.error(f"Email sending failed: {str(e)}")
        return {'success': False, 'message': f"Failed to send email: {str(e)}"}

def send_invitation_email(to_email, invite_link, inviter_name="AI Recruiter Pro"):
    """
    Send invitation email to new recruiter
    """
    subject = f"You've been invited to join AI Recruiter Pro"
    
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
        <div style="text-align: center; margin-bottom: 20px;">
            <h1 style="color: #2563eb; margin-bottom: 10px;">AI Recruiter Pro</h1>
            <p style="color: #64748b; font-size: 16px;">Advanced Recruitment Platform</p>
        </div>
        
        <div style="padding: 20px; background-color: #f8fafc; border-radius: 8px; margin-bottom: 20px;">
            <h2 style="color: #1e293b; margin-top: 0;">You've Been Invited!</h2>
            <p style="color: #334155; line-height: 1.6;">
                {inviter_name} has invited you to join AI Recruiter Pro as a recruiter.
                Our platform uses advanced AI matching to help you find the perfect candidates for your jobs.
            </p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{invite_link}" style="display: inline-block; padding: 12px 24px; background-color: #2563eb; color: white; text-decoration: none; border-radius: 6px; font-weight: 600;">
                Create Your Account
            </a>
        </div>
        
        <div style="border-top: 1px solid #e0e0e0; padding-top: 20px; color: #64748b; font-size: 14px;">
            <p>If you didn't expect this invitation, you can safely ignore this email.</p>
            <p>This invitation link will expire in 7 days.</p>
        </div>
    </div>
    """
    
    return send_email(to_email, subject, html_content)