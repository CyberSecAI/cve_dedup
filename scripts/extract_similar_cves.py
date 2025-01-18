#!/usr/bin/env python3

import json
import gzip
import pandas as pd
from pathlib import Path
import argparse
from typing import List, Dict

def load_similarity_groups(threshold: int) -> Dict:
    """Load similarity groups from json.gz file."""
    filename = f'analysis_results/similarity_groups_{threshold}.json.gz'
    with gzip.open(filename, 'rt', encoding='utf-8') as f:
        return json.load(f)

def find_similar_cves(groups: List[Dict], target_cve: str) -> List[str]:
    """Find all CVEs similar to the target CVE."""
    similar_cves = []
    
    for group in groups:
        # Check if target is the base CVE
        if group['base_cve'] == target_cve:
            similar_cves.extend([cve['cve'] for cve in group['similar_cves']])
            return similar_cves  # Return early as a CVE can only be a base once
        
        # Check if target is in similar CVEs
        for similar in group['similar_cves']:
            if similar['cve'] == target_cve:
                similar_cves.append(group['base_cve'])
                similar_cves.extend([
                    cve['cve'] for cve in group['similar_cves'] 
                    if cve['cve'] != target_cve
                ])
                return similar_cves  # Return early as a CVE can only appear once
    
    return similar_cves

def create_similarity_mapping(threshold: int) -> pd.DataFrame:
    """Create a DataFrame mapping each CVE to its similar CVEs."""
    data = load_similarity_groups(threshold)
    groups = data['groups']
    
    # Create mapping
    cve_mapping = []
    for group in groups:
        base_cve = group['base_cve']
        similar_cves = [cve['cve'] for cve in group['similar_cves']]
        
        # Add base CVE with its similar CVEs
        cve_mapping.append({
            'CVE_ID': base_cve,
            'Similar_CVEs': '|'.join(similar_cves),
            'Num_Similar': len(similar_cves)
        })
        
        # Add each similar CVE with its corresponding group
        for similar_cve in similar_cves:
            other_cves = [base_cve] + [cve for cve in similar_cves if cve != similar_cve]
            cve_mapping.append({
                'CVE_ID': similar_cve,
                'Similar_CVEs': '|'.join(other_cves),
                'Num_Similar': len(other_cves)
            })
    
    return pd.DataFrame(cve_mapping)

def main():
    parser = argparse.ArgumentParser(description='Find similar CVEs based on description similarity')
    parser.add_argument('--threshold', type=int, choices=[70, 75, 80, 85, 90, 95], default=90,
                       help='Similarity threshold to use')
    parser.add_argument('--cve', type=str, help='Specific CVE ID to look up')
    parser.add_argument('--output', type=str, default='similar_cves.csv',
                       help='Output CSV file name')
    
    args = parser.parse_args()
    
    # Create mapping DataFrame
    print(f"Creating similarity mapping for threshold {args.threshold}...")
    df = create_similarity_mapping(args.threshold)
    
    # Save to CSV
    output_file = f'similar_cves_threshold_{args.threshold}.csv'
    df.to_csv(output_file, index=False)
    print(f"Saved complete mapping to {output_file}")
    
    # If specific CVE was requested, look it up
    if args.cve:
        similar = df[df['CVE_ID'] == args.cve]
        if not similar.empty:
            print(f"\nSimilar CVEs for {args.cve}:")
            for cves in similar['Similar_CVEs']:
                print(cves.split('|'))
        else:
            print(f"\nNo similar CVEs found for {args.cve}")

if __name__ == "__main__":
    main()