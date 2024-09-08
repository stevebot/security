import subprocess
import re

# Function to get clipboard content on macOS
def get_clipboard_content():
    process = subprocess.Popen(['pbpaste'], stdout=subprocess.PIPE)
    clipboard_data, _ = process.communicate()
    return clipboard_data.decode('utf-8')

# Define a function to check for vulnerable patterns and extract the problematic content
def check_for_vulnerabilities(code):
    vulnerabilities = []

    # Example checks for command execution vulnerabilities
    exec_pattern = re.compile(r'(.*\bexec\b.*|.*\beval\b.*|.*\bos.system\b.*|.*\bsubprocess\b.*)')
    exec_matches = exec_pattern.findall(code)
    if exec_matches:
        vulnerabilities.append(("Command execution functions detected", exec_matches))

    # Example checks for SQL injection vulnerability
    sql_pattern = re.compile(r'(.*\bSELECT\b.*|.*\bINSERT\b.*|.*\bUPDATE\b.*|.*\bDELETE\b.*)', re.IGNORECASE)
    sql_matches = sql_pattern.findall(code)
    if sql_matches:
        vulnerabilities.append(("Possible SQL query detected, watch for SQL injection", sql_matches))

    # Example checks for unsafe imports
    import_pattern = re.compile(r'(.*\bimport os\b.*|.*\bimport subprocess\b.*)')
    import_matches = import_pattern.findall(code)
    if import_matches:
        vulnerabilities.append(("Insecure library imports detected", import_matches))

    # More checks can be added as needed for other vulnerabilities

    return vulnerabilities

# Main function to get clipboard content and check for vulnerabilities
def main():
    clipboard_content = get_clipboard_content()
    print("Clipboard content received. Analyzing...\n")

    vulnerabilities = check_for_vulnerabilities(clipboard_content)
    if vulnerabilities:
        for vuln_type, matches in vulnerabilities:
            print(f"{vuln_type}:")
            for match in matches:
                print(f"  {match.strip()}")
    else:
        print("No obvious vulnerabilities found.")

if __name__ == "__main__":
    main()
