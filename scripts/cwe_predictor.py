#!/usr/bin/env python3

import pandas as pd
import argparse
from pathlib import Path
from collections import Counter
from typing import Dict, List, Set
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CWEPredictor:
    def __init__(self, similarity_dir: str = 'analysis_results_csv', min_threshold: int = 70, debug: bool = False):
        """Initialize the CWE predictor with similarity data directory."""
        self.similarity_dir = Path(similarity_dir)
        self.min_threshold = min_threshold
        self.thresholds = list(range(95, min_threshold-1, -5))  # 95, 90, 85, 80, 75, 70
        self.debug = debug
        
    def load_similar_cves(self, threshold: int) -> pd.DataFrame:
        """Load similar CVE mappings for a given threshold."""
        filename = self.similarity_dir / f'similar_cves_threshold_{threshold}.csv.gz'
        try:
            return pd.read_csv(filename)
        except Exception as e:
            logger.error(f"Error loading similar CVEs for threshold {threshold}: {e}")
            return pd.DataFrame()

    def find_similar_cves(self, target_cve: str, df: pd.DataFrame) -> Set[str]:
        """Find CVEs similar to the target CVE in the DataFrame."""
        similar_cves = set()
        
        # Look for the target CVE
        row = df[df['CVE_ID'] == target_cve]
        if not row.empty:
            # Split the Similar_CVEs string into a list
            similar_str = row.iloc[0]['Similar_CVEs']
            if pd.notna(similar_str):
                similar_cves.update(similar_str.split('|'))
        
        if self.debug:
            print(f"\nFound {len(similar_cves)} similar CVEs at threshold")
            if similar_cves:
                print("Similar CVEs:", sorted(similar_cves))
                
        return similar_cves

    def predict_cwe(self, target_cve: str, cve_cwe_mapping: Dict[str, str]) -> Dict:
        """
        Predict CWE for target CVE based on similar CVEs across thresholds.
        Returns detailed analysis of CWE predictions and supporting evidence.
        """
        if self.debug:
            print(f"\nTarget CVE: {target_cve}")
            print(f"Known CWE: {cve_cwe_mapping.get(target_cve, 'Unknown')}")
            
        results = {
            'target_cve': target_cve,
            'known_cwe': cve_cwe_mapping.get(target_cve, 'Unknown'),
            'predictions': [],
            'analysis': {}
        }

        # Process each threshold
        for threshold in self.thresholds:
            if self.debug:
                print(f"\nProcessing threshold {threshold}%:")
                
            # Load similar CVEs for this threshold
            similar_df = self.load_similar_cves(threshold)
            if similar_df.empty:
                continue

            # Find similar CVEs
            similar_cves = self.find_similar_cves(target_cve, similar_df)
            if not similar_cves:
                continue

            if self.debug:
                print("\nCWE mappings for similar CVEs:")
                for cve in sorted(similar_cves):
                    cwe = cve_cwe_mapping.get(cve, 'NoCWE')
                    print(f"{cve}: {cwe}")

            # Collect CWEs from similar CVEs
            cwe_counts = Counter()
            cwe_evidence = {}
            
            for cve in similar_cves:
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
                            'threshold': threshold
                        })

            # Calculate predictions for this threshold
            if cwe_counts:
                total_similar = len(similar_cves)
                threshold_predictions = []
                
                if self.debug:
                    print(f"\nCWE counts at threshold {threshold}%:")
                    for cwe, count in cwe_counts.most_common():
                        print(f"CWE-{cwe}: {count}/{total_similar} ({count/total_similar:.1%})")
                
                for cwe, count in cwe_counts.most_common():
                    confidence = count / total_similar
                    threshold_predictions.append({
                        'cwe': cwe,
                        'count': count,
                        'confidence': confidence,
                        'evidence': cwe_evidence[cwe]
                    })
                
                results['analysis'][threshold] = {
                    'similar_cves_count': total_similar,
                    'predictions': threshold_predictions
                }

                # Add to overall predictions if not already present
                for pred in threshold_predictions:
                    if not any(p['cwe'] == pred['cwe'] for p in results['predictions']):
                        results['predictions'].append(pred)

        # Sort predictions by confidence
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
    parser.add_argument('--cve-cwe-file',  default='../nvd_cve_data/data_out/CVSSData.csv.gz',
                       help='CSV file with CVE-CWE mappings')
    parser.add_argument('--min-threshold', type=int, default=70,
                       help='Minimum similarity threshold to consider')
    parser.add_argument('--output', help='Optional output JSON file for results')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()
    
    # Load CVE-CWE mapping
    logger.info("Loading CVE-CWE mapping data...")
    cve_cwe_mapping = load_cve_cwe_data(args.cve_cwe_file)
    
    # Initialize predictor and get predictions
    predictor = CWEPredictor(min_threshold=args.min_threshold, debug=args.debug)
    results = predictor.predict_cwe(args.cve, cve_cwe_mapping)
    
    # Save or print results
    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {args.output}")
    else:
        print("\nCWE Prediction Results")
        print("=" * 50)
        print(f"Target CVE: {results['target_cve']}")
        known_cwe = results['known_cwe'].replace('CWE-', '')  # Strip CWE- prefix
        print(f"Known CWE: {known_cwe}")
        print("\nPredictions by threshold:")
        
        for threshold in sorted(results['analysis'].keys(), reverse=True):
            analysis = results['analysis'][threshold]
            print(f"\nThreshold {threshold}%:")
            print(f"Similar CVEs found: {analysis['similar_cves_count']}")
            for pred in analysis['predictions']:
                print(f"  CWE-{pred['cwe']}:")
                print(f"    Confidence: {pred['confidence']:.1%}")
                print(f"    Supporting CVEs: {pred['count']}")
                print("    Evidence (up to 3 examples):")
                for evidence in pred['evidence'][:3]:
                    print(f"      - {evidence['cve']}")

if __name__ == "__main__":
    main()