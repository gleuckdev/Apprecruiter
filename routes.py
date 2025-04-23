from flask import request, jsonify
from . import db
from .models import Submission
from flask import current_app as app

@app.route('/submit', methods=['POST'])
def submit_resume():
    data = request.get_json()

    name = data.get('name')
    email = data.get('email')
    resume = data.get('resume')  # This could be text or a file URL

    if not name or not email or not resume:
        return jsonify({'error': 'Missing required fields'}), 400

    # Check if already submitted
    existing = Submission.query.filter_by(email=email).first()
    if existing:
        return jsonify({'message': 'Resume already submitted'}), 409

    # Create new submission
    submission = Submission(name=name, email=email, resume=resume)
    db.session.add(submission)
    db.session.commit()

    return jsonify({'message': 'Resume submitted successfully'}), 201
