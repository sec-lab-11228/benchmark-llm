# Building Dataset for Linux Kernel Vulnerability Analysis

## Overview

This project is a Python-based automation tool designed for vulnerability analysis in the Linux kernel. The tool processes a list of kernel vulnerabilities, fetches relevant code changes (patches) from the Linux GitHub repository, extracts useful information about each vulnerability, and stores everything in a SQLite database. It includes automated repository management, data insertion, and vulnerability information updates.

## Features

- **Automatic GitHub Repository Cloning**: If the local Linux repository is missing, the tool automatically clones it from GitHub.
- **Database Management**: Vulnerability data from a CSV file is inserted into a SQLite database with additional computed fields.
- **Patch and Code Extraction**: The tool fetches and analyzes Git commit patches and extracts the vulnerable and fixed code blocks for each vulnerability.
- **CWE Standardization**: The tool standardizes the format of CWE identifiers for consistency.
- **Multi-threaded Processing**: Multiple vulnerabilities are processed in parallel to speed up the analysis.
- **Code Line Analysis**: The tool calculates the number of lines added or deleted in each commit and updates the database accordingly.
- **Data Cleanup**: The database is cleaned by removing entries with missing or incomplete data.

## Prerequisites

Before running the tool, ensure you have the following dependencies installed:

- Python 3.x
- `git` (for cloning the Linux repository)
- `requests` (for fetching data from GitHub)
- `pandas` (for CSV handling)
- `sqlite3` (for database management, part of the Python Standard Library)
- `concurrent.futures` (for parallel processing, part of the Python Standard Library)

### Required Python Libraries

To install the required libraries, run the following:

```bash
pip install pandas requests

## File Structure

```plaintext
.
├── README.md           # This file
├── initial_DS.csv  # CSV file containing vulnerability data
├── database.sqlite     # SQLite database (auto-generated)
├── linux_kernel/       # Directory where the Linux repository will be cloned (auto-generated)
└── build-dataset.py           # Main Python script
```

## Usage

### 1. Prepare the CSV File

The `unique_vulnerabilities.csv` file should contain vulnerability data with at least the following columns:

- `COMMIT_HASH`
- `VULNERABILITY_CVE`
- `VULNERABILITY_YEAR`
- `VULNERABILITY_CWE`
- `VULNERABILITY_CATEGORY`

This CSV file is used to populate the initial data in the SQLite database.

### 2. Running the Script

To execute the script, simply run it using Python:

```bash
python build-dataset.py
```

### 3. Process Flow

1. **Cloning the Repository**: The script will first check if the Linux kernel repository exists in the `linux_kernel/linux` directory. If not, it will automatically clone it from GitHub.
    
2. **Database Creation and Data Insertion**: If the SQLite database does not exist, it will be created. The data from `unique_vulnerabilities.csv` will be inserted into the database.
    
3. **Vulnerability Analysis**: For each vulnerability in the database, the tool:
    - Fetches the associated Git commit and extracts the patch.
    - Extracts vulnerable code segments and patched code segments.
    - Updates the database with detailed information, such as the number of files changed, lines added/deleted, and functions affected.

4. **CWE Standardization**: The script standardizes the `VULNERABILITY_CWE` field in the database to ensure uniform formatting (e.g., `CWE-79`).
    
5. **Code Line Counting**: The script calculates the number of lines in the vulnerable and patched code blocks and stores them in the database.
    
6. **Cleanup**: Entries with missing CWE or empty code blocks are removed from the database.

### 4. Example Output

On successful execution, the script will output messages indicating the progress of each step, such as cloning the repository, inserting data into the database, and processing each vulnerability.

### 5. Database Schema

The `vulnerabilities` table in the SQLite database contains the following fields:

| Column                            | Type    | Description                                                   |
|------------------------------------|---------|---------------------------------------------------------------|
| `id`                               | INTEGER | Auto-increment primary key                                    |
| `COMMIT_HASH`                      | TEXT    | The hash of the commit containing the patch                   |
| `VULNERABILITY_CVE`                | TEXT    | The CVE identifier for the vulnerability                      |
| `VULNERABILITY_YEAR`               | TEXT    | The year the vulnerability was disclosed                      |
| `VULNERABILITY_CWE`                | TEXT    | The CWE identifier for the vulnerability                      |
| `VULNERABILITY_CATEGORY`           | TEXT    | The category of the vulnerability                             |
| `DESCRIPTION_IN_PATCH`             | TEXT    | A brief description of the patch from the commit message      |
| `VULNERABLE_CODE_BLOCK`            | TEXT    | The code block containing the vulnerability                   |
| `PATCHED_CODE_BLOCK`               | TEXT    | The code block containing the fix                             |
| `NUM_FILES_CHANGED`                | INTEGER | The number of files changed in the patch                      |
| `NUM_FUNCTIONS_CHANGED`            | INTEGER | The number of functions modified in the patch                 |
| `NUM_LINES_ADDED`                  | INTEGER | The number of lines added in the patch                        |
| `NUM_LINES_DELETED`                | INTEGER | The number of lines deleted in the patch                      |
| `NUM_LINES_IN_VULNERABLE_CODE_BLOCK`| INTEGER | The number of lines in the vulnerable code block              |
| `NUM_LINES_IN_PATCHED_CODE_BLOCK`  | INTEGER | The number of lines in the patched code block                 |

## Troubleshooting

### 1. Repository Cloning Error

If there is an issue with cloning the Linux kernel repository, ensure that:

- You have an active internet connection.
- Git is installed on your system.
- You have permission to create directories in the specified path.

### 2. Database Errors

If you encounter any database-related errors, ensure that:

- The `database.sqlite` file is not locked by another process.
- The `initial_DS.csv` file is correctly formatted and includes all required fields.

### 3. Missing Commit Data

If the script is unable to fetch a commit or patch from the Linux GitHub repository, check that the `COMMIT_HASH` values in the CSV file are correct and correspond to valid commits in the repository.

# Benchmarking Framework

This Python script allows users to select and install language models before proceeding with further operations. The script dynamically configures model names and payload parameters based on user input and automates the setup for selected models.

## Features

- **Model Selection**: Users can select from a predefined list of models.
- **Model Installation**: The script installs the selected models using the appropriate commands.
- **Dynamic Configuration**: The selected model's name and parameters are extracted and used throughout the script.
- **Database Handling**: The script creates a copy of a database file, named according to the selected model, to ensure model-specific results.

## Models Available

The following models are available for selection:

- codellama-7b-instruct
- codellama-13b-instruct
- llama3.1-8b
- llama3.1-70b
- llama3-8b-instruct
- llama3-70b-instruct
- gemma2-9b
- gemma2-27b
- mistral-7b-instruct
- mixtral-8*7b-instruct

You can extend this list by adding more models to the script.

## Usage

1. **Run the Script**: Execute the script and follow the on-screen prompts to select the models you want to install.
   
    ```bash
    python generate.py
    ```

2. **Select Models**: You will be prompted to select one or more models from the available list. Enter the corresponding numbers separated by commas.

3. **Model Installation**: The selected models will be installed using the appropriate command (`ollama` or similar), and the model name and payload parameter will be set dynamically.

4. **Proceed with Operations**: Once the models are installed, the rest of the script will run using the selected model configuration.

## Example

After running the script, the process might look like this:

```
Please select the models you want to install and run. (Separate model numbers by commas)
1. codellama-7b-instruct
2. codellama-13b-instruct
3. llama3.1-8b
4. llama3.1-70b
5. llama3-8b-instruct
6. llama3-70b-instruct
7. gemma2-9b
8. gemma2-27b
9. mistral-7b-instruct
10. mixtral-8*7b-instruct
Enter the model numbers: 3, 5

Installing and running llama3.1-8b...
llama3.1-8b installed successfully.

Model selected: llama3.1-8b
Payload model parameter: llama3.1
```

## Prerequisites

- Python 3.x
- `ollama` or another relevant tool for running models
- Access to the model repository or service

## Notes

- Ensure you have the required permissions and access to install and run the selected models.
- The output directory for model-specific database copies is set to `output`.


