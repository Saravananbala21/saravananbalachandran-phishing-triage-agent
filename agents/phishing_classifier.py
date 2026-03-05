import os
from dotenv import load_dotenv
import httpx
from openai import OpenAI

# Load environment variables
load_dotenv()

# DEV ONLY: disable TLS verification for corporate SSL interception environments
http_client = httpx.Client(verify=False, timeout=60.0)

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY"),
    http_client=http_client
)


def classify_alert(alert, playbook_text: str) -> str:

    prompt = f"""
You are a SOC phishing triage assistant.

Use the following phishing triage playbook:

{playbook_text}

Analyze the email alert below and return ONLY valid JSON (no markdown, no explanations).

The JSON schema MUST be:

{{
  "alert_id": "<string>",
  "classification": "Malicious|Suspicious|Benign",
  "confidence": <integer 0-100>,
  "indicators": ["<short indicator>", "..."],
  "evidence": {{
    "sender_analysis": "<1-2 sentences>",
    "url_analysis": "<1-2 sentences>",
    "attachment_analysis": "<1-2 sentences>",
    "content_indicators": ["<short phrase>", "..."]
  }},
  "recommended_actions": ["<action>", "..."]
}}

Alert Data:
{alert}
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    return response.choices[0].message.content.strip()