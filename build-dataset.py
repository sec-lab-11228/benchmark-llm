import os
import pandas as pd
import sqlite3
import re
import requests
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed


# Constants
CSV_FILE_PATH = "unique_vulnerabilities.csv"
DB_PATH = "database.sqlite"
REPO_PATH = r"D:\OneDrive - New Mexico State University\Research\LLM\code\linux_kernel\linux"


# Database Management
class DatabaseManager:
    def __init__(self, db_path=DB_PATH):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()

    def create_vulnerabilities_table(self, existing_fields, future_fields):
        """
        Creates the vulnerabilities table with existing and future fields.
        """
        all_fields = existing_fields + list(future_fields.keys())
        field_definitions = ', '.join([f"{field} TEXT" for field in all_fields])
        self.cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            {field_definitions}
        )''')

    def insert_vulnerabilities_from_csv(self, csv_file_path, existing_fields):
        """
        Inserts data from the CSV into the vulnerabilities table.
        """
        df = pd.read_csv(csv_file_path)[existing_fields]
        for _, row in df.iterrows():
            self.cursor.execute('''
            INSERT INTO vulnerabilities (COMMIT_HASH, VULNERABILITY_CVE, VULNERABILITY_YEAR, VULNERABILITY_CWE, VULNERABILITY_CATEGORY)
            VALUES (?, ?, ?, ?, ?)
            ''', tuple(row[field] for field in existing_fields))
        self.conn.commit()

    def update_cwe_values(self):
        """
        Standardizes CWE values in the database.
        """
        self.cursor.execute("SELECT DISTINCT VULNERABILITY_CWE FROM vulnerabilities")
        cwe_values = self.cursor.fetchall()
        for cwe_value in cwe_values:
            if cwe_value[0]:
                cwe_str = str(int(float(cwe_value[0])))
                updated_cwe = f"CWE-{cwe_str}"
                self.cursor.execute("""
                    UPDATE vulnerabilities
                    SET VULNERABILITY_CWE = ?
                    WHERE VULNERABILITY_CWE = ?
                """, (updated_cwe, cwe_value[0]))
        self.conn.commit()

    def update_num_lines_in_code_blocks(self):
        """
        Updates the number of lines in vulnerable and patched code blocks.
        """
        self.cursor.execute("PRAGMA table_info(vulnerabilities)")
        columns = [info[1] for info in self.cursor.fetchall()]

        if 'NUM_LINES_IN_VULNERABLE_CODE_BLOCK' not in columns:
            self.cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN NUM_LINES_IN_VULNERABLE_CODE_BLOCK INTEGER")
        if 'NUM_LINES_IN_PATCHED_CODE_BLOCK' not in columns:
            self.cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN NUM_LINES_IN_PATCHED_CODE_BLOCK INTEGER")

        self.cursor.execute("SELECT COMMIT_HASH, VULNERABLE_CODE_BLOCK, PATCHED_CODE_BLOCK FROM vulnerabilities")
        rows = self.cursor.fetchall()

        for row in rows:
            commit_hash, vulnerable_code_block, patched_code_block = row
            num_lines_vulnerable = len(vulnerable_code_block.split('\n')) if vulnerable_code_block else 0
            num_lines_patched = len(patched_code_block.split('\n')) if patched_code_block else 0
            self.cursor.execute("""
                UPDATE vulnerabilities
                SET NUM_LINES_IN_VULNERABLE_CODE_BLOCK = ?, NUM_LINES_IN_PATCHED_CODE_BLOCK = ?
                WHERE COMMIT_HASH = ?
            """, (num_lines_vulnerable, num_lines_patched, commit_hash))
        self.conn.commit()

    def delete_invalid_records(self):
        """
        Deletes records where CWE or code blocks are invalid or empty.
        """
        self.cursor.execute("DELETE FROM vulnerabilities WHERE VULNERABILITY_CWE IS NULL OR VULNERABLE_CODE_BLOCK = ''")
        self.conn.commit()

    def get_commit_hashes(self):
        """
        Retrieves all commit hashes from the vulnerabilities table.
        """
        self.cursor.execute("SELECT COMMIT_HASH FROM vulnerabilities")
        return [row[0] for row in self.cursor.fetchall()]

    def close(self):
        """
        Closes the database connection.
        """
        self.cursor.close()
        self.conn.close()

class GitInteraction:
    def __init__(self, repo_path):
        self.repo_path = repo_path

    def get_file_at_commit(self, commit_hash, file_path):
        """Get the contents of a file at a specific commit."""
        try:
            command = ["git", "show", f"{commit_hash}:{file_path}"]
            result = subprocess.run(command, cwd=self.repo_path, text=True, capture_output=True, check=True,
                                    encoding='utf-8', errors='ignore')
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Error getting file at commit: {commit_hash} command: {command}")
            print(e.output)
            return None

    def get_patch_of_commit(self, commit_hash):
        """Fetch the patch of a specific commit from the GitHub URL."""
        url = f"https://github.com/torvalds/linux/commit/{commit_hash}.patch"
        try:
            response = requests.get(url)
            response.raise_for_status()
            patch_text = response.text
            return patch_text
        except requests.RequestException as e:
            print(f"Error fetching patch from URL: {url}")
            print(e)
            return None

    def fetch_pre_fix_vulnerable_code(self, commit_hash, file_path):
        """Fetch vulnerable code segments from the commit prior to the fixing commit."""
        parent_commit_hash = f"{commit_hash}^"
        return self.get_file_at_commit(parent_commit_hash, file_path)

    def fetch_fixed_code(self, commit_hash, file_path):
        """Fetch patched code segments from the commit."""
        return self.get_file_at_commit(commit_hash, file_path)

    def extract_function_signatures(self, code):
        """Extract function signatures from the code."""
        pattern = r'\b(?:(?:static|struct\s+\w+\s*\*?)\s+)*\w+\s+\**\w+\s*\([^)]*\)\s*\{'
        matches = re.findall(pattern, code, re.MULTILINE)
        function_signatures = [match.strip() for match in matches]
        return function_signatures

    def extract_files_and_functions_info(self, patch_text):
        """Extract the file paths and function names that contain added or deleted lines from a diff."""
        function_pattern = re.compile(r'^@@.*?@@\s*(\w[\w\s\*]*)\(')
        file_path_pattern = re.compile(r'^diff --git a/(.*?) b/')

        files_info = {}
        current_function = None
        current_file_path = None
        current_added_block = []
        current_deleted_block = []
        lines = patch_text.split('\n')

        for line in lines:
            file_match = file_path_pattern.search(line)
            if file_match:
                current_file_path = file_match.group(1).strip()
                if current_file_path not in files_info:
                    files_info[current_file_path] = {'functions': {}}
                current_function = None  # Reset current function context when encountering a new file path
                continue

            match = function_pattern.search(line)
            if match:
                current_function = match.group(1).strip()
                if current_function not in files_info[current_file_path]['functions']:
                    files_info[current_file_path]['functions'][current_function] = {'added': [], 'deleted': []}
                # Clear the current blocks when encountering a new function
                current_added_block = []
                current_deleted_block = []
            else:
                if current_file_path:
                    if line.startswith('+') and not line.startswith('+++'):
                        if current_deleted_block:
                            if current_function:
                                files_info[current_file_path]['functions'][current_function]['deleted'].append(
                                    '\n'.join(current_deleted_block))
                            else:
                                if 'deleted' not in files_info[current_file_path]:
                                    files_info[current_file_path]['deleted'] = []
                                files_info[current_file_path]['deleted'].append('\n'.join(current_deleted_block))
                            current_deleted_block = []
                        current_added_block.append(line[1:].strip())
                    elif line.startswith('-') and not line.startswith('---'):
                        if current_added_block:
                            if current_function:
                                files_info[current_file_path]['functions'][current_function]['added'].append(
                                    '\n'.join(current_added_block))
                            else:
                                if 'added' not in files_info[current_file_path]:
                                    files_info[current_file_path]['added'] = []
                                files_info[current_file_path]['added'].append('\n'.join(current_added_block))
                            current_added_block = []
                        current_deleted_block.append(line[1:].strip())
                    else:
                        if current_added_block:
                            if current_function:
                                files_info[current_file_path]['functions'][current_function]['added'].append(
                                    '\n'.join(current_added_block))
                            else:
                                if 'added' not in files_info[current_file_path]:
                                    files_info[current_file_path]['added'] = []
                                files_info[current_file_path]['added'].append('\n'.join(current_added_block))
                            current_added_block = []
                        if current_deleted_block:
                            if current_function:
                                files_info[current_file_path]['functions'][current_function]['deleted'].append(
                                    '\n'.join(current_deleted_block))
                            else:
                                if 'deleted' not in files_info[current_file_path]:
                                    files_info[current_file_path]['deleted'] = []
                                files_info[current_file_path]['deleted'].append('\n'.join(current_deleted_block))
                            current_deleted_block = []

        # Add any remaining blocks after the loop ends
        if current_added_block:
            if current_function:
                files_info[current_file_path]['functions'][current_function]['added'].append(
                    '\n'.join(current_added_block))
            else:
                if 'added' not in files_info[current_file_path]:
                    files_info[current_file_path]['added'] = []
                files_info[current_file_path]['added'].append('\n'.join(current_added_block))
        if current_deleted_block:
            if current_function:
                files_info[current_file_path]['functions'][current_function]['deleted'].append(
                    '\n'.join(current_deleted_block))
            else:
                if 'deleted' not in files_info[current_file_path]:
                    files_info[current_file_path]['deleted'] = []
                files_info[current_file_path]['deleted'].append('\n'.join(current_deleted_block))

        # Remove empty strings from the added and deleted lines
        for file_path, changes in files_info.items():
            if 'added' in changes:
                changes['added'] = list(filter(None, changes['added']))
            if 'deleted' in changes:
                changes['deleted'] = list(filter(None, changes['deleted']))
            for function_name, function_changes in changes['functions'].items():
                function_changes['added'] = list(filter(None, function_changes['added']))
                function_changes['deleted'] = list(filter(None, function_changes['deleted']))

                # Remove empty string function names
                if not function_name:
                    del changes['functions'][function_name]

        return files_info

    def extract_function(self, code, function_name):
        """ extract the entire vulnerable/patched function version of a specific function."""
        if not isinstance(code, str):
            return None

        function_start_pattern = re.compile(r'\b{}\b\s*\([^{{}}]*\)\s*{{'.format(re.escape(function_name)), re.DOTALL)
        match = function_start_pattern.search(code)

        if not match:
            return None

        start_index = match.start()

        brace_stack = []
        inside_function = False
        end_index = start_index

        for i in range(start_index, len(code)):
            if code[i] == '{':
                brace_stack.append('{')
                inside_function = True
            elif code[i] == '}':
                if brace_stack:
                    brace_stack.pop()
                    if not brace_stack:
                        end_index = i + 1
                        break

        if not inside_function or brace_stack:
            return None

        function = code[start_index:end_index]
        return function

    def is_change_within_function(self, function, changes):
        """Check if any change blocks are within the function."""
        function_lines = function.split('\n')
        change_blocks = changes['added'] + changes['deleted']

        for change in change_blocks:
            change_lines = change.split('\n')
            change_lines = [line.strip() for line in change_lines if line.strip()]

            if not change_lines:
                continue

            for i in range(len(function_lines) - len(change_lines) + 1):
                match = True
                for j in range(len(change_lines)):
                    if change_lines[j] != function_lines[i + j].strip():
                        match = False
                        break
                if match:
                    return True
        return False

    def parase_patch_header(self, patch_text):
        """Parse the patch header to extract the number of files changed, added, and deleted lines."""
        added_lines = 0
        deleted_lines = 0
        files_changed = set()

        file_pattern = re.compile(r'^diff --git a/(.*?) b/(.*?)$', re.MULTILINE)
        # find all the files changed in the diff
        matches = file_pattern.findall(patch_text)
        for match in matches:
            files_changed.add(match[0])

        # process each section starting with 'diff --git'
        sections = re.split(r'(?m)^diff --git', patch_text)
        for section in sections[1:]:  # Skip the first split as it's before the first 'diff --git'
            lines = section.split('\n')
            for line in lines:
                if line.startswith('+') and not line.startswith('+++'):
                    added_lines += 1
                elif line.startswith('-') and not line.startswith('---'):
                    deleted_lines += 1

        return len(files_changed), added_lines, deleted_lines

    def extract_commit_description(self, commit_hash):
        """Extract the commit description."""
        try:
            result = subprocess.run(['git', '-C', self.repo_path, 'log', '--format=%B', '-n', '1', commit_hash],
                                    stdout=subprocess.PIPE, text=True, encoding='utf-8')
            description = result.stdout.strip()
            return description
        except subprocess.CalledProcessError as e:
            print(f"Error extracting description for commit {commit_hash}")
            print(e.output)
            return None

    def build_code_blocks(self, files_info, commit_hash):
        """Build the vulnerable/patched code blocks from the extracted functions and added/deleted lines."""
        vulnerable_code_block = ""
        patched_code_block = ""

        # file level changes
        for file_path, file_changes in files_info.items():
            file_header_printed_vulnerable = False  # Flag to track the first entry (function or file-level change) in each file for vulnerable code
            file_header_printed_patched = False  # Flag to track the first entry (function or file-level change) in each file for patched code

            # Handle function-level changes
            functions_to_modify = []
            for function_name, changes in file_changes['functions'].items():
                if not function_name:  # Skip empty string function names
                    continue
                vulnerable_code = self.fetch_pre_fix_vulnerable_code(commit_hash, file_path)
                patched_code = self.fetch_fixed_code(commit_hash, file_path)

                vulnerable_function = self.extract_function(vulnerable_code, function_name)
                patched_function = self.extract_function(patched_code, function_name)

                # Check if changes are within the function
                if vulnerable_function and patched_function:
                    changes_within_vulnerable_function = self.is_change_within_function(vulnerable_function, changes)
                    changes_within_patched_function = self.is_change_within_function(patched_function, changes)

                    if changes_within_vulnerable_function or changes_within_patched_function:

                        if not file_header_printed_vulnerable:
                            vulnerable_code_block += f"// File path: {file_path}\n"
                            file_header_printed_vulnerable = True
                        if not file_header_printed_patched:
                            patched_code_block += f"// File path: {file_path}\n"
                            file_header_printed_patched = True
                        vulnerable_code_block += f"{vulnerable_function}\n"
                        patched_code_block += f"{patched_function}\n"
                    else:
                        # added lines
                        added_lines = '\n'.join(changes['added'])
                        deleted_lines = '\n'.join(changes['deleted'])
                        # General pattern for finding a pattern for function
                        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_\* ]*\s+[a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)'

                        # Check the function pattern in the added lines
                        added_function_signatures = re.findall(pattern, added_lines, re.MULTILINE)
                        deleted_function_signatures = re.findall(pattern, deleted_lines, re.MULTILINE)

                        # if find any pattern extract the function name and modify the function name (functions)
                        if added_function_signatures or deleted_function_signatures:
                            new_function_name = added_function_signatures[0] if added_function_signatures else \
                            deleted_function_signatures[0]
                            functions_to_modify.append((function_name, new_function_name))
                        else:
                            functions_to_modify.append((function_name, ""))

                else:
                    if 'added' in changes and changes[
                        'added']:  # if added lines contain any function signature, then fetch the entire function
                        function_signatures = self.extract_function_signatures('\n'.join(changes['added']))
                        if function_signatures:

                            new_function_name = function_signatures[0]
                            functions_to_modify.append((function_name, new_function_name))
                            patched_function = self.extract_function(patched_code, new_function_name)
                        else:
                            # append the added lines to the patched code block
                            patched_function = '\n'.join(changes['added'])
                            functions_to_modify.append((function_name, ""))

                        if not file_header_printed_patched:
                            patched_code_block += f"// File path: {file_path}\n"
                            file_header_printed_patched = True
                        patched_code_block += f"{patched_function}\n"

                    if 'deleted' in changes and changes[
                        'deleted']:  # if any deleted lines in the function, then fetch the entire function

                        function_signatures = self.extract_function_signatures('\n'.join(changes['deleted']))
                        if function_signatures:

                            new_function_name = function_signatures[0]
                            functions_to_modify.append((function_name, new_function_name))
                            vulnerable_function = self.extract_function(vulnerable_code, new_function_name)
                        else:
                            # append the deleted lines to the vulnerable code block
                            # vulnerable_code_block += f"{''.join(changes['deleted'])}\n"
                            vulnerable_function = '\n'.join(changes['deleted'])
                            if function_name in functions_to_modify:
                                continue
                            else:
                                functions_to_modify.append((function_name, ""))

                        if not file_header_printed_vulnerable:
                            vulnerable_code_block += f"// File path: {file_path}\n"
                            file_header_printed_vulnerable = True
                        vulnerable_code_block += f"{vulnerable_function}\n"

            # Add new functions after iteration
            functions_to_modify = list(set(functions_to_modify))  # Remove duplicates
            for function_name, new_function_name in functions_to_modify:
                if not function_name:  # Skip empty string function names
                    continue
                # if a function name is already in the functions, first combine the added and deleted lines and then delete the original function name
                if new_function_name in files_info[file_path]['functions']:
                    # Combine the added and deleted lines
                    combine_add = files_info[file_path]['functions'][function_name]['added'] + \
                                  files_info[file_path]['functions'][new_function_name]['added']
                    combine_del = files_info[file_path]['functions'][function_name]['deleted'] + \
                                  files_info[file_path]['functions'][new_function_name]['deleted']
                    # Assign the combined lines to the new function name
                    files_info[file_path]['functions'][new_function_name] = {'added': combine_add,
                                                                             'deleted': combine_del}
                    # Delete the original function name
                    del files_info[file_path]['functions'][function_name]
                else:
                    # Extract the value associated with the original key
                    original_value = files_info[file_path]['functions'][function_name]
                    # Delete the original function name
                    del files_info[file_path]['functions'][function_name]
                    # Assign the extracted value to the new key
                    files_info[file_path]['functions'][new_function_name] = original_value
                # print(f"function_name: {function_name} new_function_name: {new_function_name}")

                # Re-extract and re-process the modified function
                # 1. skip empty string function name
                # 2. skip if the function name is already in the functions
                if not new_function_name:
                    continue
                # if a function name is already added to the vulnerable_code_block or patched_code_block, then skip
                if new_function_name in vulnerable_code_block or new_function_name in patched_code_block:
                    continue
                vulnerable_code = self.fetch_pre_fix_vulnerable_code(commit_hash, file_path)
                patched_code = self.fetch_fixed_code(commit_hash, file_path)

                vulnerable_function = self.extract_function(vulnerable_code, new_function_name)
                patched_function = self.extract_function(patched_code, new_function_name)
                # print(f"vulnerable_function: {vulnerable_function}\n patched_function: {patched_function}\n")
                if vulnerable_function or patched_function:
                    if not file_header_printed_vulnerable:
                        vulnerable_code_block += f"// File path: {file_path}\n"
                        file_header_printed_vulnerable = True
                    if not file_header_printed_patched:
                        patched_code_block += f"// File path: {file_path}\n"
                        file_header_printed_patched = True
                    vulnerable_code_block += f"{vulnerable_function}\n"
                    patched_code_block += f"{patched_function}\n"

            # Handle file-level changes
            if 'added' in file_changes and file_changes['added']:
                if not file_header_printed_patched:
                    patched_code_block += f"// File path: {file_path}\n"
                    file_header_printed_patched = True
                patched_code_block += f"{''.join(file_changes['added'])}\n"

            if 'deleted' in file_changes and file_changes['deleted']:
                if not file_header_printed_vulnerable:
                    vulnerable_code_block += f"// File path: {file_path}\n"
                    file_header_printed_vulnerable = True
                vulnerable_code_block += f"{''.join(file_changes['deleted'])}\n"

        return files_info, vulnerable_code_block, patched_code_block

    def num_functions_changed(self, vulnerable_code_block, patched_code_block):
        """Calculate the number of functions changed between the vulnerable and patched code blocks."""
        vulnerable_functions = self.extract_function_signatures(vulnerable_code_block)
        patched_functions = self.extract_function_signatures(patched_code_block)
        unique_functions = set(vulnerable_functions + patched_functions)

        return len(unique_functions)

    def save_code_blocks(self, conn, cursor, commit_hash, vulnerable_code_block, patched_code_block):
        """Save the vulnerable code block, patched code block, number of files changed, number of functions changed, number of added lines, number of deleted lines, and the commit description to the database."""

        num_files_changed, num_lines_added, num_lines_deleted = self.parase_patch_header(
            self.get_patch_of_commit(commit_hash))
        num_functions_changed = self.num_functions_changed(vulnerable_code_block, patched_code_block)
        commit_description = self.extract_commit_description(commit_hash)

        cursor.execute('''
        UPDATE vulnerabilities
        SET DESCRIPTION_IN_PATCH = ?,
            VULNERABLE_CODE_BLOCK = ?,
            PATCHED_CODE_BLOCK = ?,
            NUM_FILES_CHANGED = ?,
            NUM_FUNCTIONS_CHANGED = ?,
            NUM_LINES_ADDED = ?,
            NUM_LINES_DELETED = ?
        WHERE COMMIT_HASH = ?
        ''', (commit_description, vulnerable_code_block, patched_code_block, num_files_changed, num_functions_changed,
              num_lines_added, num_lines_deleted, commit_hash))

        conn.commit()
        print(f"Processing complete for commit {commit_hash}.")

# Commit Processing
def process_commit(git_interaction, db_path, commit_hash):
    """
    Processes a single commit, extracting and saving code block information.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    patch_text = git_interaction.get_patch_of_commit(commit_hash)
    if patch_text:
        info = git_interaction.extract_files_and_functions_info(patch_text)
        file_info, vulnerable_code_block, patched_code_block = git_interaction.build_code_blocks(info, commit_hash)
        git_interaction.save_code_blocks(conn, cursor, commit_hash, vulnerable_code_block, patched_code_block)

    cursor.close()
    conn.close()


def process_commits_in_parallel(git_interaction, db_path, commit_hashes):
    """
    Processes a list of commit hashes in parallel.
    """
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(process_commit, git_interaction, db_path, commit_hash) for commit_hash in commit_hashes]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Error processing commit: {e}")


# Main Execution
if __name__ == "__main__":
    existing_fields = [
        "COMMIT_HASH", "VULNERABILITY_CVE", "VULNERABILITY_YEAR", "VULNERABILITY_CWE", "VULNERABILITY_CATEGORY"
    ]
    future_fields = {
        "DESCRIPTION_IN_PATCH": None,
        "VULNERABLE_CODE_BLOCK": None,
        "PATCHED_CODE_BLOCK": None,
        "NUM_FILES_CHANGED": None,
        "NUM_FUNCTIONS_CHANGED": None,
        "NUM_LINES_ADDED": None,
        "NUM_LINES_DELETED": None
    }

    # Database setup and CSV data insertion
    db_manager = DatabaseManager()
    db_manager.create_vulnerabilities_table(existing_fields, future_fields)
    db_manager.insert_vulnerabilities_from_csv(CSV_FILE_PATH, existing_fields)
    db_manager.update_cwe_values()

    # Commit processing
    git_interaction = GitInteraction(REPO_PATH)
    commit_hashes = db_manager.get_commit_hashes()
    process_commits_in_parallel(git_interaction, DB_PATH, commit_hashes)

    # Update additional fields in the database
    db_manager.update_num_lines_in_code_blocks()
    db_manager.delete_invalid_records()
    db_manager.close()

    print("All tasks completed successfully.")