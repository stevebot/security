#!/bin/bash

# Function to check for potentially dangerous patterns
check_for_dangerous_patterns() {
    local file=$1
    echo "Checking $file for potential security issues..."

    # Array of patterns to check for
    local patterns=(
        "rm -rf"             # Dangerous deletion command
        "eval"               # Can execute arbitrary code
        "system("            # Often used for system commands in C/C++/Python
        "exec("              # Can execute arbitrary commands
        "popen("             # Can execute shell commands in C/Python
        "os.system"          # Python command for executing shell commands
        "subprocess"         # Python module for spawning new processes
        "bash -c"            # Can be used to execute a string as a bash command
        "\$(( "              # Command substitution in Bash
        "\$("                # Command substitution in scripts
        "\$\(cat "           # Dangerous if combined with user input
        "\$\(curl "          # Potential for downloading and executing arbitrary code
        "\$\(wget "          # Similar risk as curl
        "\$\(python -c "     # Can execute Python code from the command line
        "\$\(perl -e "       # Can execute Perl code from the command line
        "input("             # Python input() can be dangerous if unchecked
        "import os"          # Python os module can be used for system-level operations
        "import subprocess"  # Python subprocess module for spawning processes
        "import pickle"      # Python module that can execute arbitrary code during deserialization
        "import eval"        # Python's eval is dangerous if used with untrusted data
        "import exec"        # Similar to eval
    )

    # Flag to track if any issues were found
    local issues_found=false

    # Scan the file for each pattern
    for pattern in "${patterns[@]}"; do
        if fgrep -Hn "$pattern" "$file" > /dev/null; then
            fgrep -Hn "$pattern" "$file"
            echo "Warning: Found potential security issue with pattern '$pattern' in $file"
            issues_found=true
        fi
    done

    # If no issues were found, print a message
    if [ "$issues_found" = false ]; then
        echo "No potential security issues found in $file."
    fi
}

# Check if at least one file is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <script file(s)>"
    exit 1
fi

# Iterate over all provided files
for file in "$@"; do
    if [ -f "$file" ]; then
        check_for_dangerous_patterns "$file"
    else
        echo "Error: $file not found."
    fi
done
