#!/usr/bin/env python3

import pandas as pd
import numpy as np
from rapidfuzz import fuzz
from typing import Dict, List
import unicodedata
import re
import json
import gzip
from pathlib import Path

class MultiThresholdAnalyzer:
    def __init__(self, thresholds: List[int] = [95, 90, 80]):
        """
        Initialize analyzer with multiple thresholds.
        
        Args:
            thresholds: List of similarity thresholds to analyze
        """
        self.thresholds = sorted(thresholds, reverse=True)  # Sort descending
        
    def clean_description(self, text: str) -> str:
        """Clean and normalize CVE description text."""
        if not isinstance(text, str):
            return ''

        # Normalize unicode characters
        text = unicodedata.normalize('NFKD', text).encode('ASCII', 'ignore').decode('ASCII')
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove version numbers and specific identifiers
        text = re.sub(r'\d+\.\d+\.\d+', 'VERSION', text)
        text = re.sub(r'cve-\d+-\d+', 'CVE_ID', text)
        
        # Remove newlines and carriage returns
        text = text.replace('\n', ' ').replace('\r', '')
        
        # Remove extra spaces
        text = re.sub(r'\s+', ' ', text)
        
        return text.strip()

    def analyze_multiple_thresholds(self, df: pd.DataFrame, window_size: int = 1000) -> Dict:
        """
        Analyze CVE similarities across multiple thresholds.
        
        Args:
            df: DataFrame with CVE data
            window_size: Size of comparison window
            
        Returns:
            Dictionary with analysis results for each threshold
        """
        # Add cleaned descriptions
        print("Cleaning descriptions...")
        df['Clean_Description'] = df['Description'].apply(self.clean_description)
        
        # Sort by cleaned description
        print("Sorting descriptions...")
        df = df.sort_values('Clean_Description').reset_index(drop=True)
        
        results = {}
        all_groups = {}
        
        # Analyze each threshold
        for threshold in self.thresholds:
            print(f"\nAnalyzing threshold {threshold}...")
            
            similar_groups = []
            marked = [True] * len(df)
            duplicate_count = 0
            
            for i in range(len(df)):
                if i % 1000 == 0:  # Progress indicator
                    print(f"Processing entry {i}/{len(df)}")
                    
                if not marked[i]:
                    continue
                    
                base_desc = df.iloc[i]['Clean_Description']
                group = {
                    'threshold': threshold,
                    'base_cve': df.iloc[i]['CVE'],
                    'base_description': df.iloc[i]['Description'],
                    'similar_cves': []
                }
                
                # Define comparison window
                start = max(0, i + 1)
                end = min(len(df), i + window_size + 1)
                
                for j in range(start, end):
                    if not marked[j]:
                        continue
                        
                    comp_desc = df.iloc[j]['Clean_Description']
                    
                    # Calculate similarity scores
                    scores = {
                        'ratio': fuzz.ratio(base_desc, comp_desc),
                        'token_sort_ratio': fuzz.token_sort_ratio(base_desc, comp_desc),
                        'token_set_ratio': fuzz.token_set_ratio(base_desc, comp_desc)
                    }
                    
                    # Use maximum score from different metrics
                    max_score = max(scores.values())
                    
                    if max_score >= threshold:
                        marked[j] = False
                        duplicate_count += 1
                        group['similar_cves'].append({
                            'cve': df.iloc[j]['CVE'],
                            'description': df.iloc[j]['Description'],
                            'similarity_scores': scores
                        })
                
                if group['similar_cves']:
                    similar_groups.append(group)
            
            # Calculate statistics for this threshold
            all_scores = []
            for group in similar_groups:
                for similar in group['similar_cves']:
                    all_scores.extend(similar['similarity_scores'].values())
            
            results[threshold] = {
                'statistics': {
                    'total_cves': len(df),
                    'similar_groups': len(similar_groups),
                    'total_duplicates': duplicate_count,
                    'duplicate_percentage': (duplicate_count / len(df)) * 100,
                    'average_group_size': np.mean([len(g['similar_cves']) for g in similar_groups]) if similar_groups else 0,
                    'score_statistics': {
                        'mean': np.mean(all_scores) if all_scores else 0,
                        'median': np.median(all_scores) if all_scores else 0,
                        'std': np.std(all_scores) if all_scores else 0,
                        'min': np.min(all_scores) if all_scores else 0,
                        'max': np.max(all_scores) if all_scores else 0
                    },
                    'groups_by_size': pd.Series([len(g['similar_cves']) for g in similar_groups]).value_counts().to_dict()
                },
                'groups': similar_groups[:100]  # Store top 100 groups for reference
            }
            
            all_groups[threshold] = similar_groups
            
            print(f"Found {len(similar_groups)} groups with {duplicate_count} duplicates")
            print(f"Duplicate percentage: {(duplicate_count / len(df)):.2%}")
        
        # Create output directory if it doesn't exist
        Path('analysis_results').mkdir(exist_ok=True)
        
        # Save detailed results to files
        for threshold, groups in all_groups.items():
            output_file = f'analysis_results/similarity_groups_{threshold}.json.gz'
            with gzip.open(output_file, 'wt', encoding='utf-8') as f:
                json.dump({
                    'threshold': threshold,
                    'statistics': results[threshold]['statistics'],
                    'groups': groups
                }, f, indent=2, ensure_ascii=False)
            print(f"Saved detailed results for threshold {threshold} to {output_file}")
        
        return results

def print_threshold_comparison(results: Dict):
    """Print comparison of results across thresholds."""
    print("\nThreshold Comparison:")
    print("-" * 100)
    headers = ["Threshold", "Groups", "Duplicates", "Dup %", "Avg Group Size", "Mean Score"]
    print("{:<10} {:<8} {:<10} {:<8} {:<14} {:<10}".format(*headers))
    print("-" * 100)
    
    for threshold, data in results.items():
        stats = data['statistics']
        print("{:<10} {:<8} {:<10} {:<8.2f} {:<14.2f} {:<10.2f}".format(
            threshold,
            stats['similar_groups'],
            stats['total_duplicates'],
            stats['duplicate_percentage'],
            stats['average_group_size'],
            stats['score_statistics']['mean']
        ))

def main():
    # Load CVE data
    print("Loading CVE data...")
    df = pd.read_csv('./data_in/CVSSData.csv.gz', compression='gzip')
    print(f"Loaded {len(df)} CVE entries")
    
    # Create analyzer with multiple thresholds
    analyzer = MultiThresholdAnalyzer(thresholds=[95, 90, 80])
    
    # Run analysis
    results = analyzer.analyze_multiple_thresholds(df)
    
    # Print comparison
    print_threshold_comparison(results)

if __name__ == "__main__":
    main()