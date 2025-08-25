def create_gmail_button_html(message_id: str) -> str:
    """ Generates the HTML for a styled 'Open in Gmail' button. """
    if not message_id: return ""
    url = f"https://mail.google.com/mail/u/0/#inbox/{message_id}"
    style = """
        display: inline-block; padding: 10px 18px; background-color: #AEC6CF;
        color: #111111; font-weight: 600; text-align: center;
        text-decoration: none; border-radius: 5px; border: 1px solid #333333;
        cursor: pointer; transition: transform 0.2s ease-in-out;
    """
    hover_effect = "this.style.transform='scale(1.03)';"
    unhover_effect = "this.style.transform='scale(1)';"
    return (
        f'<a href="{url}" target="_blank" style="{style}" '
        f'onmouseover="{hover_effect}" onmouseout="{unhover_effect}">'
        'Open in Gmail'
        '</a>'
    )