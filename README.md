# Security Check Script

## Overview

The `security_check.sh` script is designed to help you identify potential security vulnerabilities in scripts that you copy from the web. It scans your scripts for common dangerous patterns and outputs warnings if any suspicious code is found.

This script is particularly useful for quickly checking for issues such as code injection, command execution, and other potentially harmful practices before you run the code on your machine.

## Features

- **Pattern Matching:** Identifies common dangerous patterns like `eval`, `rm -rf`, and system calls.
- **Language Support:** Focused on Bash, Python, and general scripting languages.
- **Multiple File Support:** Scan multiple script files in a single run.

## Installation

1. **Download the Script:**
   - Save the `security_check.sh` script to your desired directory.

2. **Make the Script Executable:**
   - Open a terminal and navigate to the directory where the script is saved.
   - Run the following command to make the script executable:
     ```bash
     chmod +x security_check.sh
     ```

## Usage

To run the security check script, use the following command:

```bash
./security_check.sh <script_file_1> <script_file_2> ...
