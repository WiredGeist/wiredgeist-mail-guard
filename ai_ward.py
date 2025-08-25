# ai_ward.py (Final Structured Analysis Version)

import ollama
import json
import re

def analyze_with_ai(sender, subject, body, model_name="llama3"):
    """
    Analyzes email content using a highly structured prompt to force a methodical
    analysis from any model, preventing nuanced models from failing on obvious threats.
    """
    full_content = f"SENDER: {sender}\nSUBJECT: {subject}\nBODY:\n{body}"

    # --- NEW: Highly Structured Prompt ---
    # This prompt asks for multiple specific analysis fields instead of one general reason.
    # This forces the model to evaluate each component of the email separately.
    prompt = f"""
    You are an expert cybersecurity analyst. Analyze the following email for signs of phishing.

    Email Content:
    ---
    {full_content}
    ---

    Your entire response MUST be a single, valid JSON object. Do not write any other text.
    The JSON object MUST contain the following five keys:
    1. "verdict": A string. Must be one of "SAFE", "PROMOTIONAL/SPAM", or "PHISHING".
    2. "score": An integer from 0 (safe) to 10 (phishing).
    3. "sender_analysis": A one-sentence analysis of the SENDER's email address and domain.
    4. "content_analysis": A one-sentence analysis of the email's message for suspicious links, requests, or grammar.
    5. "summary": A final, one-sentence summary of your overall conclusion.
    """
    
    try:
        # We use the universally compatible call without format='json'
        response = ollama.chat(
            model=model_name,
            messages=[{'role': 'user', 'content': prompt}]
        )

        raw_response_content = response['message']['content']
        
        json_match = re.search(r'\{.*\}', raw_response_content, re.DOTALL)
        
        if not json_match:
            print("--- AI WARD DEBUG INFO ---")
            print(f"Model: {model_name}")
            print("Error: No JSON object was found in the model's response.")
            print("Raw Response from Model:")
            print(raw_response_content)
            print("--------------------------")
            return "ERROR", 0, "AI model did not output a detectable JSON object."

        json_string = json_match.group(0)
        
        analysis_json = json.loads(json_string)
        
        # --- NEW: Assembling the reason from structured parts ---
        verdict = analysis_json.get("verdict", "ERROR").upper()
        score = int(analysis_json.get("score", 0))
        
        # Get each part of the analysis, providing a default if missing
        summary = analysis_json.get("summary", "No summary provided.")
        sender_report = analysis_json.get("sender_analysis", "No sender analysis provided.")
        content_report = analysis_json.get("content_analysis", "No content analysis provided.")
        
        # Combine the structured parts into a single, detailed, readable reason for the UI
        reason_parts = [
            f"Summary: {summary}",
            f"Sender Analysis: {sender_report}",
            f"Content Analysis: {content_report}"
        ]
        reason = "\n\n".join(reason_parts)

        if verdict not in ["SAFE", "PROMOTIONAL/SPAM", "PHISHING"]:
            verdict = "ERROR"; score = 0; reason = f"AI returned an invalid verdict: '{verdict}'\n\n{reason}"

        return verdict, score, reason

    except json.JSONDecodeError as e:
        print(f"[AI Ward] Error decoding extracted JSON from model '{model_name}': {e}")
        return "ERROR", 0, "AI model returned malformed data that could not be parsed."
    except Exception as e:
        print(f"[AI Ward] A critical error occurred with model '{model_name}': {e}")
        return "ERROR", 0, f"Could not connect to model '{model_name}'. Is Ollama running? (Details: {e})"