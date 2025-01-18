#!/usr/bin/env python3

import pandas as pd
import json
import gzip
from pathlib import Path
from typing import Dict, List
import argparse

def find_highest_similarity_groups(cve_list: List[str], results_dir: str = 'analysis_results') -> pd.DataFrame:
    """
    Find the highest similarity threshold group for each CVE.
    
    Args:
        cve_list: List of CVE IDs to analyze
        results_dir: Directory containing similarity group results
        
    Returns:
        DataFrame with similarity information for each CVE
    """
    # Get all similarity group files
    results_path = Path(results_dir)
    
    # Fixed file name parsing
    def get_threshold(filepath):
        try:
            # Extract number from similarity_groups_95.json.gz format
            return int(filepath.stem.split('_')[-1].split('.')[0])
        except (IndexError, ValueError):
            return 0
    
    similarity_files = sorted(
        results_path.glob('similarity_groups_*.json.gz'),
        key=get_threshold,
        reverse=True
    )
    
    if not similarity_files:
        raise FileNotFoundError(f"No similarity group files found in {results_dir}")
    
    print(f"Found {len(similarity_files)} threshold files to process")
    
    # Create a dictionary to store highest threshold matches
    cve_matches = {cve: {
        'highest_threshold': None,
        'group_size': None,
        'similarity_scores': None,
        'similar_cves': None,
        'is_base': False
    } for cve in cve_list}
    
    # Process each threshold file from highest to lowest
    print("Processing similarity groups...")
    for file_path in similarity_files:
        threshold = get_threshold(file_path)
        print(f"Checking threshold {threshold}...")
        
        try:
            with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                data = json.load(f)
            
            # Process each group
            for group in data['groups']:
                base_cve = group['base_cve']
                similar_cves = [item['cve'] for item in group['similar_cves']]
                
                # Check base CVE
                if base_cve in cve_matches and cve_matches[base_cve]['highest_threshold'] is None:
                    cve_matches[base_cve].update({
                        'highest_threshold': threshold,
                        'group_size': len(similar_cves) + 1,
                        'similar_cves': similar_cves,
                        'is_base': True
                    })
                
                # Check similar CVEs
                for idx, similar in enumerate(group['similar_cves']):
                    cve = similar['cve']
                    if cve in cve_matches and cve_matches[cve]['highest_threshold'] is None:
                        other_cves = [base_cve] + [x['cve'] for x in group['similar_cves'] if x['cve'] != cve]
                        cve_matches[cve].update({
                            'highest_threshold': threshold,
                            'group_size': len(similar_cves) + 1,
                            'similarity_scores': similar['similarity_scores'],
                            'similar_cves': other_cves,
                            'is_base': False
                        })
                        
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            continue
    
    # Convert to DataFrame
    results = []
    for cve, info in cve_matches.items():
        row = {
            'CVE': cve,
            'Highest_Threshold': info['highest_threshold'],
            'Group_Size': info['group_size'],
            'Is_Base_CVE': info['is_base'],
            'Ratio_Score': None,
            'Token_Sort_Score': None,
            'Token_Set_Score': None,
            'Similar_CVEs': None
        }
        
        if info['similarity_scores']:
            row.update({
                'Ratio_Score': info['similarity_scores']['ratio'],
                'Token_Sort_Score': info['similarity_scores']['token_sort_ratio'],
                'Token_Set_Score': info['similarity_scores']['token_set_ratio']
            })
        
        if info['similar_cves']:
            row['Similar_CVEs'] = '|'.join(info['similar_cves'])
        
        results.append(row)
    
    df = pd.DataFrame(results)
    
    # Organize columns
    columns = ['CVE', 'Highest_Threshold', 'Group_Size', 'Is_Base_CVE', 
              'Ratio_Score', 'Token_Sort_Score', 'Token_Set_Score', 'Similar_CVEs']
    df = df.reindex(columns=columns)
    
    return df

def main():
    parser = argparse.ArgumentParser(description='Find highest similarity threshold for CVEs')
    parser.add_argument('input_file', help='CSV file containing CVE IDs')
    parser.add_argument('--output', default='cve_similarities.csv', 
                       help='Output CSV file name')
    args = parser.parse_args()
    
    # Read input CVEs
    print(f"Reading CVEs from {args.input_file}...")
    df = pd.read_csv(args.input_file)
    if 'CVE' not in df.columns:
        raise ValueError("Input CSV must have a 'CVE' column")
    
    cve_list = df['CVE'].tolist()
    print(f"Found {len(cve_list)} CVEs to analyze")
    
    # Find similarity groups
    results_df = find_highest_similarity_groups(cve_list)
    
    # Save results
    results_df.to_csv(args.output, index=False)
    print(f"\nResults saved to {args.output}")
    
    # Print summary
    print("\nSummary:")
    print(f"Total CVEs analyzed: {len(results_df)}")
    print(f"CVEs with matches: {len(results_df[results_df['Highest_Threshold'].notna()])}")
    print("\nDistribution by threshold:")
    threshold_counts = results_df['Highest_Threshold'].value_counts().sort_index(ascending=False)
    for threshold, count in threshold_counts.items():
        if pd.notna(threshold):
            print(f"Threshold {threshold:3.0f}: {count:5d} CVEs")

if __name__ == "__main__":
    main()