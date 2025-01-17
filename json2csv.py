# json2csv.py
# usage: 
#   python3 json2csv.py

import json
import csv
import pandas as pd
from pathlib import Path
from typing import Dict, List, Iterator


output_file = './data_in/CVSSData.csv.gz'
in_file = './data_in/nvd.jsonl'


class CVEProcessor:
    def __init__(self, input_file: str, output_file: str):
        self.input_file = input_file
        self.output_file = output_file
        self.rejected_count = 0
        self.reject_marker_count = 0  # Count of "** REJECT **"
        self.reject_reason_count = 0  # Count of "Rejected reason:"
        self.processed_count = 0
        # Ensure output directory exists
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        
    def read_json_content(self) -> Iterator[dict]:
        """Read JSON Lines file content."""
        with open(self.input_file, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError as e:
                        print(f"Error decoding JSON line: {e}")
                        continue

    def is_rejected_cve(self, description: str) -> bool:
        """
        Check if the CVE description indicates it was rejected.
        Returns True if description starts with either '** REJECT **' or 'Rejected reason:'
        """
        if not description:
            return False
            
        desc = description.strip()
        if desc.startswith('** REJECT **'):
            self.reject_marker_count += 1
            return True
        elif desc.startswith('Rejected reason:'):
            self.reject_reason_count += 1
            return True
        return False

    def extract_cve_data(self) -> pd.DataFrame:
        """Extract CVE IDs and descriptions into a DataFrame, excluding rejected CVEs."""
        cve_data: List[Dict[str, str]] = []
        
        for entry in self.read_json_content():
            try:
                # Handle both dictionary and list cases
                if isinstance(entry, list):
                    items = entry
                else:
                    items = [entry]
                
                for item in items:
                    self.processed_count += 1
                    
                    if not isinstance(item, dict):
                        continue
                        
                    cve_info = item.get('cve')
                    if not cve_info:
                        continue
                        
                    cve_id = cve_info.get('id')
                    if not cve_id:
                        continue
                    
                    # Find English description
                    description = None
                    descriptions = cve_info.get('descriptions', [])
                    if isinstance(descriptions, list):
                        for desc in descriptions:
                            if isinstance(desc, dict) and desc.get('lang') == 'en':
                                description = desc.get('value')
                                break
                    
                    # Skip rejected CVEs
                    if description and not self.is_rejected_cve(description):
                        cve_data.append({
                            'CVE': cve_id,
                            'Description': description
                        })
                    else:
                        self.rejected_count += 1
                    
            except Exception as e:
                print(f"Error processing entry: {e}")
                import traceback
                print(traceback.format_exc())
                continue
        
        # Create DataFrame and save to CSV
        df = pd.DataFrame(cve_data)
        df.to_csv(self.output_file, index=False, quoting=csv.QUOTE_ALL, escapechar='\\', compression='gzip')
        
        # Print summary statistics
        print(f"\nProcessing Summary:")
        print(f"Total entries processed: {self.processed_count}")
        print(f"Total rejected CVEs: {self.rejected_count}")
        print(f" - With '** REJECT **': {self.reject_marker_count}")
        print(f" - With 'Rejected reason:': {self.reject_reason_count}")
        print(f"Valid CVEs saved: {len(df)}")
        print(f"Rejection rate: {(self.rejected_count/self.processed_count)*100:.2f}%")
        print(f"\nSaved {len(df)} valid CVE entries to {self.output_file}")
        
        return df

def main():
    processor = CVEProcessor(in_file, output_file)
    df = processor.extract_cve_data()
    print("\nFirst few entries:")
    print(df.head())
    print(f"\nTotal valid CVEs saved: {len(df)}")

if __name__ == "__main__":
    main()