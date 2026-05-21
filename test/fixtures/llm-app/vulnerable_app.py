"""
Vulnerable LLM Application - Test Fixture for osdo-llm-scan
OWASP GenAI Security Top 10 vulnerabilities included:
- LLM01: Prompt Injection
- LLM02: Insecure Output Handling
- LLM05: Insecure Model Serialization
- LLM06: Sensitive Information Disclosure
"""
import openai
import pickle
import subprocess

# LLM06: Hardcoded API key
openai.api_key = "sk-test-1234567890abcdef"

def chat_with_llm(user_input: str) -> str:
    """
    LLM01: Prompt Injection - User input directly in prompt
    """
    # VULNERABLE: User input directly interpolated
    prompt = f"You are a helpful assistant. User says: {user_input}"
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful assistant"},
            {"role": "user", "content": prompt}  # LLM01: Unsanitized input
        ]
    )
    return response.choices[0].message.content


def execute_llm_response(user_input: str):
    """
    LLM02: Insecure Output Handling - Executing LLM output
    """
    response = chat_with_llm(user_input)
    
    # VULNERABLE: Executing LLM output directly
    exec(response)  # LLM02: Dangerous function with LLM output
    

def run_llm_command(user_input: str):
    """
    LLM02: Another insecure output handling pattern
    """
    response = chat_with_llm(user_input)
    
    # VULNERABLE: Shell command with LLM output
    subprocess.call(response, shell=True)  # LLM02: Command injection risk


def load_custom_model(model_path: str):
    """
    LLM05: Insecure Model Serialization
    """
    # VULNERABLE: Pickle deserialization
    with open(model_path, 'rb') as f:
        model = pickle.load(f)  # LLM05: Arbitrary code execution risk
    return model


def log_conversation(user_input: str, response: str):
    """
    LLM06: Sensitive Information Disclosure
    """
    # VULNERABLE: Logging PII to console
    email = "user@example.com"
    credit_card = "4111-1111-1111-1111"
    
    # LLM06: PII in prompt
    enriched_prompt = f"User {email} with card {credit_card} asks: {user_input}"
    print(f"Prompt: {enriched_prompt}")  # LLM06: Logging sensitive data
    print(f"Response: {response}")


def dangerous_agent_function():
    """
    LLM08: Excessive Agency - Function with dangerous permissions
    """
    # VULNERABLE: LLM can call shell commands
    functions = [
        {
            "type": "function",
            "function": {
                "name": "run_shell",
                "description": "Execute arbitrary shell commands",
                "parameters": {"command": {"type": "string"}}
            }
        }
    ]
    return functions
