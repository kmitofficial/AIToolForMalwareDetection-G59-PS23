import subprocess
import re

def get_wifi_status():
    try:
        # For Windows
        result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True, check=True)
        
        # Extract the 'State' information using regular expression
        pattern = re.compile(r'State\s*:\s*(\S+)', re.IGNORECASE)
        match = pattern.search(result.stdout)
        
        # Return the WiFi status or 'Not found' if information is not available
        return match.group(1) if match else 'Not found'

    except subprocess.CalledProcessError as e:
        return f'Error: {e.returncode}, {e.stderr}'

def check_and_print_wifi_status():
    status = get_wifi_status()
    return status

# Example usage