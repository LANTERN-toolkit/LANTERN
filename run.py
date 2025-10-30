# /run.py
from app import create_app
import os
import google.generativeai as genai

app = create_app()

if __name__ == '__main__':
    # Configure the API key when the application starts
    if app.config['GOOGLE_API_KEY']:
        genai.configure(api_key=app.config['GOOGLE_API_KEY'])
        print("Google Generative AI SDK configured successfully.")
    else:
        print("ERROR: GOOGLE_API_KEY not found. Please set it in your .env file.")

    app.run(debug=True)