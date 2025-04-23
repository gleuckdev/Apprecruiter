# AI Recruiter Pro - Setup Instructions

## Requirements
- Python 3.8+ 
- PostgreSQL database
- OpenAI API key

## Environment Variables
Ensure these environment variables are set:
- `DATABASE_URL` - PostgreSQL connection string
- `OPENAI_API_KEY` - Your OpenAI API key 
- `SESSION_SECRET` - Secret for session management
- `MAILGUN_API_KEY` (optional) - For email functionality
- `MAILGUN_DOMAIN` (optional) - For email functionality

## Installation Steps

1. Extract the code archive:
```
tar -xzvf airecruiter_code.tar.gz
```

2. Install dependencies:
```
pip install -r requirements.txt
```

3. Database setup:
```
python -c "from app import db; db.create_all()"
```

4. Run migrations:
```
python migrations.py
```

5. (Optional) Add test data:
```
python add_test_data.py
```

6. Start the application:
```
gunicorn --bind 0.0.0.0:5000 main:app
```

## Test User Credentials
- Email: demo@example.com
- Password: password123

## Feature Notes

### Manual Location and Experience Fields
The updated job creation form allows recruiters to manually input:
- Location information
- Years of experience requirements

These manual inputs will override any values extracted by the AI from the job description. If left blank, the AI will attempt to extract this information automatically.

### Testing the New Feature
1. Log in with test credentials
2. Go to the dashboard
3. Click "Create New Job"
4. Enter job description
5. Fill in the optional Location and Experience fields
6. Submit the form
7. Verify that your manual inputs appear in the job listing

See CHANGES.md for a detailed explanation of the implementation.