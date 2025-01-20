#!/usr/bin/env python3

import json
import gzip
import pandas as pd
from pathlib import Path
import argparse
from collections import Counter
from typing import Dict, List, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CWEPredictor:
    def __init__(self, similarity_dir: str = 'analysis_results', min_threshold: int = 70):
        """Initialize the CWE predictor with similarity data directory."""
        self.similarity_dir = Path(similarity_dir)
        self.min_threshold = min_threshold
        self.thresholds = list(range(95, min_threshold-1, -5))  # 95, 90, 85, 80, 75, 70
        
    def load_similarity_groups(self, threshold: int) -> Dict:
        """Load similarity groups for a given threshold."""
        filename = self.similarity_dir / f'similarity_groups_{threshold}.json.gz'
        try:
            with gzip.open(filename, 'rt', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading similarity groups for threshold {threshold}: {e}")
            return None

    def find_similar_cves(self, target_cve: str, threshold: int) -> List[Dict]:
        """Find CVEs similar to the target CVE at given threshold."""
        data = self.load_similarity_groups(threshold)
        if not data:
            return []

        similar_entries = []
        for group in data['groups']:
            # Check if target is the base CVE
            if group['base_cve'] == target_cve:
                similar_entries.extend(group['similar_cves'])
                break
            
            # Check if target is in similar CVEs
            for similar in group['similar_cves']:
                if similar['cve'] == target_cve:
                    # Add base CVE with similarity scores
                    similar_entries.append({
                        'cve': group['base_cve'],
                        'description': group['base_description'],
                        'similarity_scores': similar['similarity_scores']
                    })
                    # Add other similar CVEs
                    similar_entries.extend([
                        s for s in group['similar_cves']
                        if s['cve'] != target_cve
                    ])
                    break
        
        return similar_entries

    def predict_cwe(self, target_cve: str, cve_cwe_mapping: Dict[str, str]) -> Dict:
        """
        Predict CWE for target CVE based on similar CVEs across thresholds.
        Returns detailed analysis of CWE predictions and supporting evidence.
        """
        results = {
            'target_cve': target_cve,
            'known_cwe': cve_cwe_mapping.get(target_cve, 'Unknown'),
            'predictions': [],
            'analysis': {}
        }
        
        # Check each threshold from highest to lowest
        for threshold in self.thresholds:
            similar_cves = self.find_similar_cves(target_cve, threshold)
            if not similar_cves:
                continue
                
            # Collect CWEs from similar CVEs
            cwe_counts = Counter()
            cwe_evidence = {}
            
            for entry in similar_cves:
                cve = entry['cve']
                if cve in cve_cwe_mapping:
                    cwes = cve_cwe_mapping[cve].split('|')
                    for cwe in cwes:
                        # Strip CWE- prefix if present
                        clean_cwe = cwe.replace('CWE-', '')
                        cwe_counts[clean_cwe] += 1
                        if clean_cwe not in cwe_evidence:
                            cwe_evidence[clean_cwe] = []
                        cwe_evidence[clean_cwe].append({
                            'cve': cve,
                            'similarity_scores': entry.get('similarity_scores', {})
                        })
            
            if cwe_counts:
                # Calculate confidence scores
                total_similar = len(similar_cves)
                predictions = []
                for cwe, count in cwe_counts.most_common():
                    confidence = count / total_similar
                    predictions.append({
                        'cwe': cwe,
                        'count': count,
                        'confidence': confidence,
                        'evidence': cwe_evidence[cwe]
                    })
                
                results['analysis'][threshold] = {
                    'similar_cves_count': total_similar,
                    'predictions': predictions
                }
                
                # Add to overall predictions if not already present
                for pred in predictions:
                    if not any(p['cwe'] == pred['cwe'] for p in results['predictions']):
                        results['predictions'].append(pred)
        
        # Sort overall predictions by confidence
        results['predictions'].sort(key=lambda x: x['confidence'], reverse=True)
        
        return results

def load_cve_cwe_data(filepath: str) -> Dict[str, str]:
    """Load CVE-CWE mapping from CSV file."""
    try:
        df = pd.read_csv(filepath, compression='gzip')
        return dict(zip(df['CVE'], df['CWE']))
    except Exception as e:
        logger.error(f"Error loading CVE-CWE data: {e}")
        return {}

def main():
    parser = argparse.ArgumentParser(description='Predict CWE for a CVE based on similar CVEs')
    parser.add_argument('cve', help='Target CVE ID to analyze')
    parser.add_argument('--cve-cwe-file', default='data_in/CVSSData.csv.gz',
                       help='CSV file with CVE-CWE mappings')
    parser.add_argument('--min-threshold', type=int, default=70,
                       help='Minimum similarity threshold to consider')
    parser.add_argument('--output', help='Optional output JSON file for results')
    
    args = parser.parse_args()
    
    # Load CVE-CWE mapping
    logger.info("Loading CVE-CWE mapping data...")
    cve_cwe_mapping = load_cve_cwe_data(args.cve_cwe_file)
    
    # Initialize predictor and get predictions
    predictor = CWEPredictor(min_threshold=args.min_threshold)
    results = predictor.predict_cwe(args.cve, cve_cwe_mapping)
    
    # Save or print results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {args.output}")
    else:
        print("\nCWE Prediction Results")
        print("=" * 50)
        print(f"Target CVE: {results['target_cve']}")
        known_cwe = results['known_cwe'].replace('CWE-', '')  # Strip CWE- prefix
        print(f"Known CWE: {known_cwe}")
        print("\nPredictions (in order of confidence):")
        for pred in results['predictions']:
            print(f"\nCWE-{pred['cwe']}:")
            print(f"  Confidence: {pred['confidence']:.1%}")
            print(f"  Supporting CVEs: {pred['count']}")
            print("  Evidence:")
            for evidence in pred['evidence'][:3]:  # Show top 3 similar CVEs
                scores = evidence['similarity_scores']
                if scores:
                    best_score = max(scores.values())
                    print(f"    - {evidence['cve']} (similarity: {best_score}%)")

if __name__ == "__main__":
    main()