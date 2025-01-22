#!/usr/bin/env python3

import json
from pathlib import Path

def convert_to_jsonl(input_file: str, output_file: str):
    """
    Convert NVD JSON file to JSONL format.
    Each line will contain a single CVE entry.
    
    Args:
        input_file (str): Path to input JSON file
        output_file (str): Path to output JSONL file
    """
    # Create output directory if it doesn't exist
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    
    # Read input JSON
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    # Write each CVE entry as a separate line
    with open(output_file, 'w', encoding='utf-8') as f:
        for entry in data:
            # Convert the entry to a JSON string and write it as a single line
            json_line = json.dumps(entry, ensure_ascii=False)
            f.write(json_line + '\n')

def main():
    input_file = "./data_in/nvd.json"
    output_file = "./data_in/nvd.jsonl"
    
    try:
        convert_to_jsonl(input_file, output_file)
        print(f"Successfully converted {input_file} to {output_file}")
    except Exception as e:
        print(f"Error converting file: {e}")

if __name__ == "__main__":
    main()