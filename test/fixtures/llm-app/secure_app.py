"""
Secure LLM Application - Best Practices for osdo-llm-scan comparison
"""
import os
from typing import Optional
import openai
import torch
import html

# Secure: API key from environment
openai.api_key = os.environ.get("OPENAI_API_KEY")


def sanitize_input(user_input: str) -> str:
    """Sanitize user input before including in prompts."""
    # Remove potential injection patterns
    sanitized = html.escape(user_input)
    sanitized = sanitized.replace("ignore previous", "")
    sanitized = sanitized.replace("system:", "")
    return sanitized[:1000]  # Limit length


def chat_with_llm(user_input: str) -> str:
    """
    Secure: Sanitized input with proper message structure
    """
    clean_input = sanitize_input(user_input)
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful assistant. Only provide text responses."},
            {"role": "user", "content": clean_input}
        ],
        max_tokens=500  # Limit output
    )
    return response.choices[0].message.content


def validate_llm_output(response: str) -> Optional[str]:
    """
    Secure: Validate LLM output before use
    """
    # Never execute LLM output
    # Validate format and content
    if len(response) > 10000:
        return None
    if any(dangerous in response.lower() for dangerous in ["import os", "subprocess", "exec("]):
        return None
    return response


def load_model_secure(model_path: str):
    """
    Secure: Use weights_only for safe model loading
    """
    # Safe: Using weights_only=True
    model = torch.load(model_path, weights_only=True)
    return model


def log_conversation_safe(user_input: str, response: str):
    """
    Secure: No PII logging, sanitized output
    """
    # Redact any potential PII
    safe_input = "[REDACTED]" if "@" in user_input else user_input[:50]
    print(f"Conversation logged: {len(safe_input)} chars input")
