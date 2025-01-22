#!/usr/bin/env python3

import pandas as pd
import json
import gzip
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict
import argparse

class CWESimilarityAnalyzer:
    def __init__(self, similarity_dir: str = 'analysis_results'):
        self.similarity_dir = Path(similarity_dir)

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
        cve_to_cwe = dict(zip(cve_cwe_df['CVE'], cve_cwe_df['CWE']))
        
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
            
            # Get CWEs for all CVEs in group
            group_cwes = set()
            cve_cwe_pairs = []
            for cve in all_cves:
                if cve in cve_to_cwe:
                    cwe = cve_to_cwe[cve]
                    group_cwes.add(cwe)
                    cve_cwe_pairs.append((cve, cwe))
            
            # Analyze group
            group_size = len(all_cves)
            unique_cwes = len(group_cwes)
            is_consistent = unique_cwes == 1  # All CVEs have same CWE
            
            group_analysis = {
                'base_cve': base_cve,
                'group_size': group_size,
                'unique_cwes': unique_cwes,
                'is_consistent': is_consistent,
                'cwes': list(group_cwes),
                'cve_cwe_pairs': cve_cwe_pairs
            }
            
            groups_analysis.append(group_analysis)
            total_groups += 1
            if is_consistent:
                consistent_groups += 1
        
        # Calculate statistics
        consistency_ratio = consistent_groups / total_groups if total_groups > 0 else 0
        
        # Analyze CWE distribution in inconsistent groups
        cwe_cooccurrence = defaultdict(int)
        for group in groups_analysis:
            if not group['is_consistent']:
                cwes = group['cwes']
                for cwe1 in cwes:
                    for cwe2 in cwes:
                        if cwe1 < cwe2:  # Count each pair only once
                            cwe_cooccurrence[(cwe1, cwe2)] += 1
        
        return {
            'summary': {
                'total_groups': total_groups,
                'consistent_groups': consistent_groups,
                'consistency_ratio': consistency_ratio,
                'threshold': threshold
            },
            'groups': groups_analysis,
            'cwe_cooccurrence': dict(cwe_cooccurrence)
        }

    def print_analysis_results(self, results: Dict):
        """Print detailed analysis results."""
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
        for (cwe1, cwe2), count in sorted_pairs[:10]:
            print(f"CWE-{cwe1} & CWE-{cwe2}: {count} occurrences")
        
        # Analyze group sizes
        group_sizes = [g['group_size'] for g in results['groups']]
        consistent_sizes = [g['group_size'] for g in results['groups'] if g['is_consistent']]
        
        print("\nGroup Size Analysis:")
        print("-" * 50)
        print(f"Average Group Size (All): {sum(group_sizes)/len(group_sizes):.2f}")
        print(f"Average Group Size (Consistent): {sum(consistent_sizes)/len(consistent_sizes):.2f}")

def main():
    parser = argparse.ArgumentParser(description='Analyze CWE consistency in similar CVE groups')
    #parser.add_argument('cve_cwe_file', help='CSV file with CVE and CWE mappings')
    parser.add_argument('--threshold', type=int, default=90, help='Similarity threshold to analyze')

    args = parser.parse_args()
    
    # Read CVE-CWE mappings
    #df = pd.read_csv(args.cve_cwe_file)
    
    df = pd.read_csv('../nvd_cve_data/data_out/CVSSData.csv.gz', compression='gzip')

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