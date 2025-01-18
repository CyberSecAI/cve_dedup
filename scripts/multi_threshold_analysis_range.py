#!/usr/bin/env python3

import pandas as pd
import numpy as np
from rapidfuzz import fuzz
from typing import Dict, List, Tuple
import unicodedata
import re
import json
import gzip
from pathlib import Path
from multiprocessing import Pool, cpu_count
from functools import partial
from tqdm import tqdm
import gc

class MultiThresholdAnalyzer:
    def __init__(self, thresholds: List[int] = None):
        if thresholds is None:
            self.thresholds = list(range(70, 100, 5))
        else:
            self.thresholds = sorted(thresholds, reverse=True)
        
        # Precompile regex patterns
        self.version_pattern = re.compile(r'\d+\.\d+\.\d+')
        self.cve_pattern = re.compile(r'cve-\d+-\d+')
        self.space_pattern = re.compile(r'\s+')
    
    def clean_description(self, text: str) -> str:
        """Optimized description cleaning."""
        if not isinstance(text, str):
            return ''
        
        # Batch operations to reduce string copies
        text = (unicodedata.normalize('NFKD', text.lower())
               .encode('ASCII', 'ignore')
               .decode('ASCII')
               .replace('\n', ' ')
               .replace('\r', ' '))
        
        # Use precompiled patterns
        text = self.version_pattern.sub('VERSION', text)
        text = self.cve_pattern.sub('CVE_ID', text)
        text = self.space_pattern.sub(' ', text)
        
        return text.strip()

    def analyze_chunk(self, args: Tuple[pd.DataFrame, int, int]) -> List[Dict]:
        """Memory-optimized chunk analysis."""
        chunk_df, threshold, window_size = args
        similar_groups = []
        chunk_len = len(chunk_df)
        marked = np.ones(chunk_len, dtype=bool)  # Using numpy array for efficiency
        
        # Convert descriptions to list for faster access
        descriptions = chunk_df['Clean_Description'].tolist()
        cves = chunk_df['CVE'].tolist()
        original_desc = chunk_df['Description'].tolist()
        
        for i in range(chunk_len):
            if not marked[i]:
                continue
            
            base_desc = descriptions[i]
            similar_cves = []
            
            # Compare with subsequent entries within window
            end_idx = min(chunk_len, i + window_size + 1)
            for j in range(i + 1, end_idx):
                if not marked[j]:
                    continue
                
                # Calculate similarity score using the fastest metric first
                ratio = fuzz.ratio(base_desc, descriptions[j])
                if ratio >= threshold:
                    token_sort = fuzz.token_sort_ratio(base_desc, descriptions[j])
                    token_set = fuzz.token_set_ratio(base_desc, descriptions[j])
                    max_score = max(ratio, token_sort, token_set)
                    
                    if max_score >= threshold:
                        marked[j] = False
                        similar_cves.append({
                            'cve': cves[j],
                            'description': original_desc[j],
                            'similarity_scores': {
                                'ratio': ratio,
                                'token_sort_ratio': token_sort,
                                'token_set_ratio': token_set
                            }
                        })
            
            if similar_cves:
                similar_groups.append({
                    'threshold': threshold,
                    'base_cve': cves[i],
                    'base_description': original_desc[i],
                    'similar_cves': similar_cves
                })
        
        del descriptions, cves, original_desc
        gc.collect()  # Force garbage collection
        return similar_groups

    def analyze_multiple_thresholds(self, df: pd.DataFrame, window_size: int = 1000) -> Dict:
        """Memory-optimized multi-threshold analysis."""
        print("Cleaning descriptions...")
        # Use pandas apply with precompiled patterns
        df['Clean_Description'] = df['Description'].apply(self.clean_description)
        
        print("Sorting descriptions...")
        df = df.sort_values('Clean_Description').reset_index(drop=True)
        
        # Create output directory
        Path('analysis_results').mkdir(exist_ok=True)
        
        results = {}
        chunk_size = min(50000, len(df) // cpu_count())  # Optimized chunk size
        
        for threshold in tqdm(self.thresholds, desc="Processing thresholds"):
            print(f"\nAnalyzing threshold {threshold}...")
            
            # Create chunks more efficiently
            chunks = [(df.iloc[i:i + chunk_size].copy(), threshold, window_size)
                     for i in range(0, len(df), chunk_size)]
            
            # Process chunks in parallel
            with Pool() as pool:
                chunk_results = list(tqdm(
                    pool.imap(self.analyze_chunk, chunks),
                    total=len(chunks),
                    desc=f"Processing chunks"
                ))
            
            # Combine results efficiently
            similar_groups = [group for chunk in chunk_results for group in chunk]
            del chunk_results
            gc.collect()
            
            # Calculate statistics efficiently
            duplicate_count = sum(len(group['similar_cves']) for group in similar_groups)
            
            # Collect scores efficiently
            all_scores = []
            for group in similar_groups:
                for similar in group['similar_cves']:
                    scores = similar['similarity_scores']
                    all_scores.extend([scores['ratio'], scores['token_sort_ratio'], scores['token_set_ratio']])
            
            if all_scores:
                score_stats = {
                    'mean': float(np.mean(all_scores)),
                    'median': float(np.median(all_scores)),
                    'std': float(np.std(all_scores)),
                    'min': float(np.min(all_scores)),
                    'max': float(np.max(all_scores))
                }
            else:
                score_stats = {
                    'mean': 0, 'median': 0, 'std': 0, 'min': 0, 'max': 0
                }
            
            # Save results immediately to free memory
            output_file = f'analysis_results/similarity_groups_{threshold}.json.gz'
            result_data = {
                'threshold': threshold,
                'statistics': {
                    'total_cves': len(df),
                    'similar_groups': len(similar_groups),
                    'total_duplicates': duplicate_count,
                    'duplicate_percentage': (duplicate_count / len(df)) * 100,
                    'average_group_size': float(np.mean([len(g['similar_cves']) for g in similar_groups])) if similar_groups else 0,
                    'score_statistics': score_stats,
                    'groups_by_size': pd.Series([len(g['similar_cves']) for g in similar_groups]).value_counts().to_dict()
                },
                'groups': similar_groups
            }
            
            with gzip.open(output_file, 'wt', encoding='utf-8') as f:
                json.dump(result_data, f, indent=2, ensure_ascii=False)
            
            # Store only summary for final results
            results[threshold] = {
                'statistics': result_data['statistics'],
                'groups': similar_groups[:100]
            }
            
            print(f"\nThreshold {threshold}:")
            print(f"Found {len(similar_groups)} groups with {duplicate_count} duplicates")
            print(f"Duplicate percentage: {(duplicate_count / len(df)):.2%}")
            
            # Clear memory
            del similar_groups, result_data
            gc.collect()
        
        return results

def print_threshold_comparison(results: Dict):
    """Print detailed comparison of results across thresholds."""
    print("\nThreshold Comparison:")
    print("-" * 120)
    
    # Enhanced headers with more information
    headers = [
        "Threshold", "Groups", "Duplicates", "Dup %", 
        "Avg Group", "Mean Score", "Med Score", "Min Score", "Max Score"
    ]
    
    print("{:<10} {:<8} {:<10} {:<8} {:<10} {:<10} {:<10} {:<10} {:<10}".format(*headers))
    print("-" * 120)
    
    # Sort thresholds in descending order
    for threshold in sorted(results.keys(), reverse=True):
        stats = results[threshold]['statistics']
        score_stats = stats['score_statistics']
        
        print("{:<10} {:<8} {:<10} {:<8.2f} {:<10.2f} {:<10.2f} {:<10.2f} {:<10.2f} {:<10.2f}".format(
            threshold,
            stats['similar_groups'],
            stats['total_duplicates'],
            stats['duplicate_percentage'],
            stats['average_group_size'],
            score_stats['mean'],
            score_stats['median'],
            score_stats['min'],
            score_stats['max']
        ))
    
    print("\nSummary Statistics:")
    print("-" * 50)
    
    # Add summary statistics for the highest threshold (most strict)
    highest_threshold = max(results.keys())
    stats = results[highest_threshold]['statistics']
    print(f"Total CVEs analyzed: {stats['total_cves']:,}")
    print(f"Total unique CVEs: {stats['total_cves'] - stats['total_duplicates']:,}")
    print(f"Total duplicate CVEs found: {stats['total_duplicates']:,}")
    print(f"Overall duplicate percentage: {stats['duplicate_percentage']:.2f}%")

def main():
    print("Loading CVE data...")
    # Use chunked reading for large files
    df = pd.read_csv('./data_in/CVSSData.csv.gz', compression='gzip',
                     dtype={'CVE': str, 'Description': str})  # Specify dtypes
    print(f"Loaded {len(df)} CVE entries")
    
    analyzer = MultiThresholdAnalyzer()
    results = analyzer.analyze_multiple_thresholds(df)
    print_threshold_comparison(results)

if __name__ == "__main__":
    main()