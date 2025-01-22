#!/usr/bin/env python3

import pandas as pd
import json
import gzip
import ast
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict
import argparse

class CWESimilarityAnalyzer:
    def __init__(self, similarity_dir: str = 'analysis_results'):
        self.similarity_dir = Path(similarity_dir)

    def parse_cwe_list(self, cwe_str: str) -> List[str]:
        """
        Parse CWE string representation of a list into actual list of CWEs.
        
        Args:
            cwe_str: String representation of CWE list (e.g., "['CWE-79', 'CWE-200']")
            
        Returns:
            List of CWE strings
        """
        try:
            if pd.isna(cwe_str):
                return []
            return ast.literal_eval(cwe_str)
        except:
            return []

    def analyze_cwe_groups(self, cve_cwe_df: pd.DataFrame, threshold: int = 90) -> Dict:
        """
        Analyze CWE consistency within similar CVE groups.
        
        Args:
            cve_cwe_df: DataFrame with 'CVE' and 'CWE' columns
            threshold: Similarity threshold to analyze
            
        Returns:
            Dictionary with analysis results
        """
        # Create CVE to CWE mapping
        cve_to_cwe = {row['CVE']: self.parse_cwe_list(row['CWE']) 
                      for _, row in cve_cwe_df.iterrows()}
        
        # Load similarity groups
        file_path = self.similarity_dir / f'similarity_groups_{threshold}.json.gz'
        with gzip.open(file_path, 'rt') as f:
            similarity_data = json.load(f)
        
        groups_analysis = []
        total_groups = 0
        consistent_groups = 0
        
        for group in similarity_data['groups']:
            # Get all CVEs in the group
            base_cve = group['base_cve']
            similar_cves = [s['cve'] for s in group['similar_cves']]
            all_cves = [base_cve] + similar_cves
            
            # Get CWEs for all CVEs in group that are in our mapping
            group_cwes = set()
            cve_cwe_pairs = []
            valid_cves = []
            
            for cve in all_cves:
                if cve in cve_to_cwe:
                    cwes = cve_to_cwe[cve]
                    if cwes:  # Only count CVEs that have CWEs
                        group_cwes.update(cwes)
                        cve_cwe_pairs.append((cve, cwes))
                        valid_cves.append(cve)
            
            # Skip groups with no valid CVEs or CWEs
            if not valid_cves or not group_cwes:
                continue
                
            # Analyze group
            group_size = len(valid_cves)
            unique_cwes = len(group_cwes)
            
            # Consider group consistent if all valid CVEs share at least one common CWE
            common_cwes = set(cve_to_cwe[valid_cves[0]])
            for cve in valid_cves[1:]:
                common_cwes.intersection_update(set(cve_to_cwe[cve]))
            is_consistent = len(common_cwes) > 0
            
            group_analysis = {
                'base_cve': base_cve,
                'group_size': group_size,
                'unique_cwes': unique_cwes,
                'is_consistent': is_consistent,
                'common_cwes': list(common_cwes),
                'all_cwes': list(group_cwes),
                'cve_cwe_pairs': cve_cwe_pairs
            }
            
            groups_analysis.append(group_analysis)
            total_groups += 1
            if is_consistent:
                consistent_groups += 1
        
        # Calculate statistics
        consistency_ratio = consistent_groups / total_groups if total_groups > 0 else 0
        
        # Analyze CWE co-occurrence in inconsistent groups
        cwe_cooccurrence = defaultdict(int)
        for group in groups_analysis:
            if not group['is_consistent']:
                cwes = group['all_cwes']
                for cwe1 in cwes:
                    for cwe2 in cwes:
                        if cwe1 < cwe2:  # Count each pair only once
                            cwe_cooccurrence[(cwe1, cwe2)] += 1
        
        # Convert tuple keys to strings for JSON serialization
        json_safe_cooccurrence = {
            f"{cwe1}||{cwe2}": count 
            for (cwe1, cwe2), count in cwe_cooccurrence.items()
        }
        
        return {
            'summary': {
                'total_groups': total_groups,
                'consistent_groups': consistent_groups,
                'consistency_ratio': consistency_ratio,
                'threshold': threshold
            },
            'groups': groups_analysis,
            'cwe_cooccurrence': json_safe_cooccurrence
        }

    def print_analysis_results(self, results: Dict):
        """Print detailed analysis results with mapping statistics."""
        # Print mapping coverage statistics first
        print("\nCVE-CWE Mapping Statistics")
        print("=" * 50)
        summary = results['summary']
        print("\nCWE Consistency Analysis Results")
        print("=" * 50)
        print(f"Similarity Threshold: {summary['threshold']}")
        print(f"Total Groups Analyzed: {summary['total_groups']}")
        print(f"Consistent Groups: {summary['consistent_groups']}")
        print(f"Consistency Ratio: {summary['consistency_ratio']:.2%}")
        
        print("\nTop CWE Co-occurrences in Inconsistent Groups:")
        print("-" * 50)
        cooccurrence = results['cwe_cooccurrence']
        sorted_pairs = sorted(cooccurrence.items(), key=lambda x: x[1], reverse=True)
        for pair_str, count in sorted_pairs[:10]:
            cwe1, cwe2 = pair_str.split('||')
            print(f"{cwe1} & {cwe2}: {count} occurrences")
        
        # Analyze group sizes
        group_sizes = [g['group_size'] for g in results['groups']]
        consistent_sizes = [g['group_size'] for g in results['groups'] if g['is_consistent']]
        
        print("\nGroup Size Analysis:")
        print("-" * 50)
        print(f"Average Group Size (All): {sum(group_sizes)/len(group_sizes):.2f}")
        if consistent_sizes:
            print(f"Average Group Size (Consistent): {sum(consistent_sizes)/len(consistent_sizes):.2f}")
        
        # Print examples of consistent and inconsistent groups
        print("\nExample Groups:")
        print("-" * 50)
        
        # Consistent group example
        consistent = next((g for g in results['groups'] if g['is_consistent']), None)
        if consistent:
            print("\nConsistent Group Example:")
            print(f"Base CVE: {consistent['base_cve']}")
            print(f"Common CWEs: {consistent['common_cwes']}")
            print(f"Group Size: {consistent['group_size']}")
            
        # Inconsistent group example
        inconsistent = next((g for g in results['groups'] if not g['is_consistent']), None)
        if inconsistent:
            print("\nInconsistent Group Example:")
            print(f"Base CVE: {inconsistent['base_cve']}")
            print(f"All CWEs: {inconsistent['all_cwes']}")
            print(f"Group Size: {inconsistent['group_size']}")

def main():
    parser = argparse.ArgumentParser(description='Analyze CWE consistency in similar CVE groups')
    parser.add_argument('--threshold', type=int, default=90, help='Similarity threshold to analyze')
    parser.add_argument('--input', default='../nvd_cve_data/data_out/CVSSData.csv.gz', 
                      help='Input CSV file path')

    args = parser.parse_args()
    
    # Read CVE-CWE mappings
    df = pd.read_csv(args.input, compression='gzip' if args.input.endswith('.gz') else None)
    if not {'CVE', 'CWE'}.issubset(df.columns):
        raise ValueError("Input CSV must have 'CVE' and 'CWE' columns")
    
    # Run analysis
    analyzer = CWESimilarityAnalyzer()
    results = analyzer.analyze_cwe_groups(df, args.threshold)
    
    # Print results
    analyzer.print_analysis_results(results)
    
    # Save detailed results
    output_file = f'cwe_consistency_analysis_{args.threshold}.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nDetailed results saved to {output_file}")

if __name__ == "__main__":
    main()