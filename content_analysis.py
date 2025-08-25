def content_analysis(email_body):
    """
    Analyzes email content for suspicious keywords and phrases, returning a numerical score.
    """
    # Using a dictionary to assign a "weight" or "score" to each suspicious term.
    # Higher scores are for terms that are more likely to be in phishing emails.
    suspicious_terms = {
        # High-Risk Phrases (5 points)
        'verify your account': 5,
        'account has been suspended': 5,
        'unusual sign-in activity': 5,
        'confirm your identity': 5,
        'your password has expired': 5,
        'account compromise': 5,
        
        # Medium-Risk Keywords (3 points)
        'action required': 3,
        'security alert': 3,
        'update your payment': 3,
        'login attempt': 3,
        
        # Low-Risk Keywords (1 point)
        'invoice': 1,
        'payment': 1,
        'shipping confirmation': 1,
        'verify': 1,
        'password': 1,
        'account': 1,
        'urgent': 1,
    }

    # We are no longer checking for generic patterns like '.com' or 'http' in the body,
    # as they cause too many false positives.

    total_score = 0
    reasons_found = []
    
    email_body_lower = email_body.lower()

    for term, score in suspicious_terms.items():
        if term in email_body_lower:
            total_score += score
            reasons_found.append(f"'{term}' (Score: +{score})")

    return total_score, reasons_found
