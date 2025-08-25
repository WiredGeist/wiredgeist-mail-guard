# ai_ward.py ("Threat Strategist")

import ollama
import json
import re

def analyze_with_ai(analysis_payload: dict, model_name: str):
    """
    Analyzes a full intelligence report using an LLM to infer the attacker's
    tactics, goals, and provide actionable advice.
    """
    json_report = json.dumps(analysis_payload, indent=2)

    system_message = """
    You are a Lead Threat Intelligence Analyst and Behavioral Psychologist.
    You will be given a JSON report containing technical data about a suspicious email.
    Your job is to go beyond the raw data and provide a strategic assessment.

    Your entire response MUST be a single, valid JSON object and nothing else.
    The JSON object must contain the following five keys:

    1.  "attack_vector": A string identifying the specific type of attack.
        Examples: "Credential Harvesting", "Malware Delivery", "Social Engineering Scam", "Advance-Fee Fraud".
    
    2.  "deception_tactic": A one-sentence analysis of the psychological trick used.
        Examples: "The email creates a false sense of urgency by claiming an account issue.", "The email uses the lure of social status ('verification badge') to entice a click.", "The email impersonates a trusted authority (TikTok Support) to lower the target's defenses."

    3.  "threat_hypothesis": A one-sentence, educated guess about the attacker.
        Examples: "This is likely a low-skill operator using a pre-built phishing kit.", "The use of multiple, unrelated domains suggests a more organized attacker managing a portfolio of infrastructure.", "The generic nature of the email suggests a wide-net campaign, not a targeted attack."
    
    4.  "recommended_actions": A short, actionable list of 2-3 steps the user should take.
        Example: ["Do NOT click any links.", "Delete the email immediately.", "Verify any account notifications by logging into the official website or app directly."]
        
    5.  "final_verdict": A string. Must be one of "SAFE", "SUSPICIOUS", or "PHISHING".
    """

    user_prompt = f"Here is the security analysis report in JSON format. Provide your strategic assessment as a single JSON object.\n\n```json\n{json_report}\n```"

    try:
        # Use the format='json' parameter for models that support it
        response = ollama.chat(
            model=model_name,
            messages=[
                {'role': 'system', 'content': system_message},
                {'role': 'user', 'content': user_prompt},
            ],
            options={'temperature': 0.2}, # Lower temperature for more deterministic, factual output
            format='json' # Ask for a JSON response directly
        )

        content = response['message']['content']
        analysis_json = json.loads(content)
        
        verdict = analysis_json.get("final_verdict", "ERROR").upper()
        
        # Assemble a rich, detailed report for the UI
        report_parts = [
            f"Attack Vector: {analysis_json.get('attack_vector', 'N/A')}",
            f"Deception Tactic: {analysis_json.get('deception_tactic', 'N/A')}",
            f"Threat Hypothesis: {analysis_json.get('threat_hypothesis', 'N/A')}",
            "\nRecommended Actions:",
            "- " + "\n- ".join(analysis_json.get('recommended_actions', ['N/A']))
        ]
        
        full_report = "\n".join(report_parts)
        
        score_map = {"PHISHING": 9, "SUSPICIOUS": 5, "SAFE": 0, "ERROR": 0}
        score = score_map.get(verdict, 0)
        
        return verdict, score, full_report

    except Exception as e:
        print(f"AI Ward Error: {e}")
        # Fallback for models that fail JSON mode or have other issues
        return "ERROR", 0, f"The AI model failed to produce a valid strategic analysis. (Details: {e})"
