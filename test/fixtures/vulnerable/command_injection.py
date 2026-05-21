import os
import subprocess

def run_command_os(user_input):
    """Vulnerable: Command injection via os.system."""
    # VULNERABLE: Command Injection
    os.system("echo " + user_input)


def run_command_popen(user_input):
    """Vulnerable: Command injection via Popen with shell=True."""
    # VULNERABLE: Command Injection
    subprocess.Popen("cat " + user_input, shell=True)
