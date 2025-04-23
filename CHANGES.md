# AI Recruiter Pro - Location and Experience Manual Input Feature

## Changes Overview

This update adds the ability for recruiters to manually input location and years of experience information when creating job listings. These manual inputs will override any values that the AI extracts from the job description.

## Files Modified

### 1. templates/dashboard.html
Added input fields for:
- Location (Optional) - String field with placeholder "e.g., San Francisco, Remote, etc."
- Years of Experience (Optional) - String field with placeholder "e.g., 3-5 years, 5+ years, etc."

The form now captures these inputs and sends them to the server along with the job description.

### 2. static/js/main.js
Modified the `setupJobForm()` function to:
- Capture values from the new form fields
- Add them to the payload JSON if they have values (non-empty)
- Display them in the success message when job creation is successful

### 3. app.py
Modified the `/api/jobs` API endpoint (create_job function) to:
- Priority: Use manually provided values for location and experience if they exist
- Fallback: Use AI-extracted values if manual values are not provided
- Return more detailed job information in the API response, including location and experience

## Database
No database changes were required as the `jobs` table already had:
- `location` (String, 100 characters)
- `experience` (String, 50 characters)

## Testing
Tests confirmed that:
- Form displays the new fields
- Values are correctly sent to the backend
- Manual values override AI-extracted ones
- Values appear in the UI when jobs are listed

## Notes
- This enhances the recruiter experience by allowing manual override of AI-extracted values
- Job matching functionality continues to work as before
- The UI clearly displays the location and experience in job listings
