import os
import json
from typing import Any
from langchain_community.tools import DuckDuckGoSearchRun
from langchain_core.tools import tool

def get_web_search_tool():
    """Returns a DuckDuckGo web search tool."""
    return DuckDuckGoSearchRun(name="UnifiedWebSearch")

def get_file_tools(base_dir: str):
    """Returns a list of tools for reading and writing files within base_dir."""
    
    @tool
    def write_file(relative_path: str, content: Any) -> str:
        """Write content to a file at a path relative to the project output directory. Parent directories will be created automatically."""
        clean_path = os.path.normpath(relative_path).lstrip("/")
        if clean_path.startswith("..") or os.path.isabs(clean_path):
            return "Error: Invalid path. Path must be relative and inside the project folder."
        
        # Resolve content string
        if isinstance(content, (dict, list)):
            content_str = json.dumps(content, indent=2)
        elif isinstance(content, str):
            stripped = content.strip()
            # Handle double-serialized JSON strings
            if (stripped.startswith('"') and stripped.endswith('"')) or (stripped.startswith("'{") and stripped.endswith("}'")):
                try:
                    parsed = json.loads(stripped)
                    if isinstance(parsed, (dict, list)):
                        content_str = json.dumps(parsed, indent=2)
                    else:
                        content_str = str(parsed)
                except Exception:
                    content_str = content
            else:
                content_str = content
        else:
            content_str = str(content)

        target_path = os.path.join(base_dir, clean_path)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(content_str)
        return f"Successfully wrote to {relative_path}"

    @tool
    def read_file(relative_path: str) -> str:
        """Read content from a file at a path relative to the project output directory."""
        clean_path = os.path.normpath(relative_path).lstrip("/")
        if clean_path.startswith("..") or os.path.isabs(clean_path):
            return "Error: Invalid path. Path must be relative and inside the project folder."
        target_path = os.path.join(base_dir, clean_path)
        if not os.path.exists(target_path):
            return f"Error: File {relative_path} does not exist."
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                return f.read()
        except UnicodeDecodeError:
            return f"Error: File '{relative_path}' could not be decoded as UTF-8 text. It might be a binary or non-text file."
        except Exception as e:
            return f"Error reading file '{relative_path}': {e}"

    @tool
    def list_files() -> str:
        """List all files currently in the project output directory."""
        if not os.path.exists(base_dir):
            return "No files in the output directory yet."
        files_list = []
        for root, dirs, files in os.walk(base_dir):
            # Exclude package/build directories to avoid returning too many files (e.g. node_modules)
            dirs[:] = [d for d in dirs if d not in ('node_modules', '.next', '.git', 'dist', 'build', '.cache')]
            for file in files:
                if file.startswith('.') or file == 'Thumbs.db':
                    continue
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, base_dir)
                files_list.append(rel_path)
        if not files_list:
            return "No files in the output directory yet."
        return "\n".join(files_list)

    @tool
    def edit_file(relative_path: str, target_text: str, replacement_text: str) -> str:
        """Edit a file by replacing a specific unique target_text block with replacement_text. 
        Only the specified block will be changed; the rest of the file remains intact.
        Ensure target_text matches the file content exactly (including whitespace and indentation)."""
        clean_path = os.path.normpath(relative_path).lstrip("/")
        if clean_path.startswith("..") or os.path.isabs(clean_path):
            return "Error: Invalid path. Path must be relative and inside the project folder."
        target_path = os.path.join(base_dir, clean_path)
        if not os.path.exists(target_path):
            return f"Error: File {relative_path} does not exist."
        
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            return f"Error: File '{relative_path}' could not be decoded as UTF-8 text. It might be a binary or non-text file."
        except Exception as e:
            return f"Error reading file '{relative_path}': {e}"
            
        if target_text not in content:
            return f"Error: The target_text was not found in {relative_path}. Please read the file first to check its exact content and indentation."
            
        # Count occurrences to avoid ambiguous replacements
        occurrences = content.count(target_text)
        if occurrences > 1:
            return f"Error: The target_text occurs {occurrences} times in the file. Please provide a larger/more unique block of text to replace."
            
        new_content = content.replace(target_text, replacement_text)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(new_content)
            
        return f"Successfully edited {relative_path} (replaced target block)."

    return [write_file, read_file, list_files, edit_file]

def parse_and_write_files(text: str, base_dir: str):
    """
    Parses file content from text (either as markdown code blocks, JSON lines, or XML tool calls)
    and writes them to base_dir.
    """
    import re
    written_files = []
    
    # 1. Try parsing JSON lines/blocks (handling nested braces and escapes)
    def find_json_objects(s: str):
        objs = []
        start = 0
        while True:
            pos = s.find('{', start)
            if pos == -1:
                break
            depth = 0
            in_string = False
            escape = False
            end_pos = -1
            for i in range(pos, len(s)):
                char = s[i]
                if escape:
                    escape = False
                    continue
                if char == '\\':
                    escape = True
                    continue
                if char == '"':
                    in_string = not in_string
                    continue
                if not in_string:
                    if char == '{':
                        depth += 1
                    elif char == '}':
                        depth -= 1
                        if depth == 0:
                            end_pos = i
                            break
            if end_pos != -1:
                objs.append(s[pos:end_pos+1])
                start = end_pos + 1
            else:
                start = pos + 1
        return objs

    matches = find_json_objects(text)
    for match in matches:
        try:
            # Clean up invalid escapes (e.g. escaped single quotes \' inside json strings)
            cleaned = match.replace("\\'", "'")
            data = json.loads(cleaned)
            name = data.get("name") or data.get("type")
            if name == "write_file":
                args = data.get("arguments") or data.get("parameters") or {}
                rel_path = args.get("relative_path")
                content = args.get("content")
                if rel_path and content is not None:
                    clean_path = os.path.normpath(rel_path).lstrip("/")
                    if not (clean_path.startswith("..") or os.path.isabs(clean_path)):
                        target_path = os.path.join(base_dir, clean_path)
                        os.makedirs(os.path.dirname(target_path), exist_ok=True)
                        with open(target_path, "w", encoding="utf-8") as f:
                            f.write(str(content))
                        written_files.append(rel_path)
        except Exception as e:
            print(f"Error parsing JSON line tool call: {e}")
            
    # 2. Try parsing XML-like tool calls (Qwen / Ollama style)
    # Format:
    # <tool_call>
    # <function=write_file>
    # <parameter=relative_path>
    # path
    # </parameter>
    # <parameter=content>
    # content
    # </parameter>
    # </tool_call>
    xml_matches = re.finditer(r'<function=write_file>', text)
    for match in xml_matches:
        start_idx = match.end()
        # Search for relative_path parameter
        path_match = re.search(r'<parameter=relative_path>\s*(.*?)\s*</parameter>', text[start_idx:], re.DOTALL)
        path = None
        if path_match:
            path = path_match.group(1).strip()
        else:
            # Fallback if no closing tag yet for path
            path_start_match = re.search(r'<parameter=relative_path>\s*([a-zA-Z0-9_\-\.\/]+)', text[start_idx:], re.DOTALL)
            if path_start_match:
                path = path_start_match.group(1).strip()
            
        # Search for content parameter
        content_match = re.search(r'<parameter=content>\s*(.*?)\s*</parameter>', text[start_idx:], re.DOTALL)
        content = None
        if content_match:
            content = content_match.group(1)
        else:
            # If no closing </parameter> is found (e.g. truncated), take everything from <parameter=content> to end
            content_start_match = re.search(r'<parameter=content>\s*(.*)', text[start_idx:], re.DOTALL)
            if content_start_match:
                content = content_start_match.group(1)
                # Strip trailing tool_call/parameter tags if any are partially present
                content = re.sub(r'</parameter>\s*</tool_call>\s*$', '', content)
                content = re.sub(r'</parameter>\s*$', '', content)
                
        if path and content is not None:
            clean_path = os.path.normpath(path).lstrip("/")
            if not (clean_path.startswith("..") or os.path.isabs(clean_path)):
                target_path = os.path.join(base_dir, clean_path)
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with open(target_path, "w", encoding="utf-8") as f:
                    f.write(content.strip())
                if path not in written_files:
                    written_files.append(path)

    # 3. Try parsing Markdown blocks with file indicators
    segments = text.split("```")
    for i in range(1, len(segments), 2):
        code_block = segments[i]
        pre_text = segments[i-1]
        pre_lines = [line.strip() for line in pre_text.split("\n") if line.strip()]
        
        path = None
        
        # Method A: Check explicit file/path headers in preceding lines
        if pre_lines:
            for line in reversed(pre_lines[-4:]):
                clean_line = re.sub(r'[*`#\[\]]', '', line).strip()
                clean_line = clean_line.rstrip(':').strip()
                clean_line = re.sub(r'^\s*\d+[\s\.\)-]+', '', clean_line).strip()
                match = re.search(r'(?:file|path|filename)\s*:\s*([a-zA-Z0-9_\-\.\/]+)', clean_line, re.IGNORECASE)
                if match:
                    path = match.group(1)
                    break
                if re.match(r'^[a-zA-Z0-9_\-\.\/]+\.[a-zA-Z0-9]+$', clean_line):
                    path = clean_line
                    break
                    
        lines = code_block.split("\n")
        
        # Method B: Check first line comment of code block (e.g. /* styles.css */, // main.js, <!-- index.html -->)
        if not path and lines:
            first_line = lines[0].strip()
            comment_match = re.search(r'(?:\/\*|\/\/|<!--)\s*([a-zA-Z0-9_\-\.\/]+\.[a-zA-Z0-9]+)\s*(?:\*\/|-->)?', first_line)
            if comment_match:
                path = comment_match.group(1)
                
        # Method C: Check conversational preceding text for target files (index.html, styles.css, main.js)
        if not path and pre_text:
            pre_text_lower = pre_text.lower()
            if "index.html" in pre_text_lower:
                path = "index.html"
            elif "styles.css" in pre_text_lower or "style.css" in pre_text_lower:
                path = "styles.css"
            elif "main.js" in pre_text_lower or "script.js" in pre_text_lower:
                path = "main.js"
                
        if path:
            if lines:
                first_line = lines[0].strip().lower()
                if first_line in ['tsx', 'ts', 'jsx', 'js', 'html', 'css', 'json', 'python', 'py', 'sh', 'bash', 'yaml', 'yml', 'javascript']:
                    block_content = "\n".join(lines[1:])
                else:
                    block_content = code_block
            else:
                block_content = code_block
                
            clean_path = os.path.normpath(path).lstrip("/")
            if not (clean_path.startswith("..") or os.path.isabs(clean_path)):
                target_path = os.path.join(base_dir, clean_path)
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with open(target_path, "w", encoding="utf-8") as f:
                    f.write(block_content.strip())
                if path not in written_files:
                    written_files.append(path)
                    
    return written_files


