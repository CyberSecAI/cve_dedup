#!/usr/bin/env python3

import pandas as pd
import argparse
from pathlib import Path
from collections import Counter
from typing import Dict, List, Set
import logging
import json
import csv
import os
from tqdm import tqdm

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
        
        row = df[df['CVE_ID'] == target_cve]
        if not row.empty:
            similar_str = row.iloc[0]['Similar_CVEs']
            if pd.notna(similar_str):
                similar_cves.update(similar_str.split('|'))
                
        return similar_cves

    def predict_cwe(self, target_cve: str, cve_cwe_mapping: Dict[str, str]) -> tuple[Dict, List[Dict]]:
        """
        Predict CWE for target CVE based on similar CVEs across thresholds.
        Returns both detailed results and CSV-formatted summary rows.
        """
        results = {
            'target_cve': target_cve,
            'known_cwe': cve_cwe_mapping.get(target_cve, 'Unknown'),
            'predictions': [],
            'analysis': {}
        }
        
        # List to store CSV rows
        csv_rows = []

        for threshold in self.thresholds:
            similar_df = self.load_similar_cves(threshold)
            if similar_df.empty:
                continue

            similar_cves = self.find_similar_cves(target_cve, similar_df)
            if not similar_cves:
                continue

            # Collect CWEs from similar CVEs
            cwe_counts = Counter()
            cwe_evidence = {}
            
            for cve in similar_cves:
                if cve in cve_cwe_mapping:
                    cwes = cve_cwe_mapping[cve].split('|')
                    for cwe in cwes:
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
                
                for cwe, count in cwe_counts.most_common():
                    confidence = count / total_similar
                    threshold_predictions.append({
                        'cwe': cwe,
                        'count': count,
                        'confidence': confidence,
                        'evidence': cwe_evidence[cwe]
                    })
                    
                    # Add row for CSV
                    csv_rows.append({
                        'cve_id': target_cve,
                        'threshold': threshold,
                        'cwe': cwe,
                        'similar_cves_count': total_similar,
                        'count': count,
                        'confidence': float(f"{confidence:.3f}")
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
        return results, csv_rows

def load_cve_cwe_data(filepath: str) -> Dict[str, str]:
    """Load CVE-CWE mapping from CSV file."""
    try:
        df = pd.read_csv(filepath, compression='gzip')
        return dict(zip(df['CVE'], df['CWE']))
    except Exception as e:
        logger.error(f"Error loading CVE-CWE data: {e}")
        return {}

def get_all_cves(similarity_dir: str, threshold: int = 95) -> Set[str]:
    """Get list of all CVEs from the highest threshold similarity file."""
    try:
        df = pd.read_csv(os.path.join(similarity_dir, f'similar_cves_threshold_{threshold}.csv.gz'))
        return set(df['CVE_ID'].unique())
    except Exception as e:
        logger.error(f"Error loading CVEs from similarity file: {e}")
        return set()

def append_to_csv(csv_rows: List[Dict], output_file: str, mode: str = 'a'):
    """Append or write rows to CSV file."""
    fieldnames = ['cve_id', 'threshold', 'cwe', 'similar_cves_count', 'count', 'confidence']
    file_exists = os.path.exists(output_file)
    
    if mode == 'w' or not file_exists:
        mode = 'w'
    else:
        mode = 'a'
        
    with open(output_file, mode, newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if mode == 'w':
            writer.writeheader()
        writer.writerows(csv_rows)

def process_cve(cve: str, predictor: CWEPredictor, cve_cwe_mapping: Dict[str, str], 
                output_dir: str, csv_file: str, debug: bool = False) -> None:
    """Process a single CVE and save results."""
    try:
        # Get predictions
        results, csv_rows = predictor.predict_cwe(cve, cve_cwe_mapping)
        
        # Save detailed JSON
        json_file = os.path.join(output_dir, 'CVE', f"{cve}.json")
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
            
        # Append to CSV
        append_to_csv(csv_rows, csv_file)
        
        if debug:
            print(f"\nProcessed {cve}")
            print(f"Known CWE: {results['known_cwe']}")
            print(f"Number of predictions: {len(results['predictions'])}")
            
    except Exception as e:
        logger.error(f"Error processing {cve}: {e}")

def main():
    parser = argparse.ArgumentParser(description='Predict CWE for CVEs based on similar CVEs')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--cve', help='Single CVE ID to analyze')
    group.add_argument('--all', action='store_true', help='Process all CVEs')
    parser.add_argument('--cve-cwe-file', default='../nvd_cve_data/data_out/CVSSData.csv.gz',
                       help='CSV file with CVE-CWE mappings')
    parser.add_argument('--min-threshold', type=int, default=70,
                       help='Minimum similarity threshold to consider')
    parser.add_argument('--output-dir', default='data_out/CVE_similarity',
                       help='Directory for output files')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()
    
    # Create output directories
    os.makedirs(args.output_dir, exist_ok=True)
    os.makedirs(os.path.join(args.output_dir, 'CVE'), exist_ok=True)
    
    # Define output files
    csv_file = os.path.join(args.output_dir, "cve_similarity.csv")
    
    # Load CVE-CWE mapping
    logger.info("Loading CVE-CWE mapping data...")
    cve_cwe_mapping = load_cve_cwe_data(args.cve_cwe_file)
    
    # Initialize predictor
    predictor = CWEPredictor(min_threshold=args.min_threshold, debug=args.debug)
    
    if args.all:
        # Get all CVEs and process them
        logger.info("Loading list of all CVEs...")
        all_cves = get_all_cves(predictor.similarity_dir)
        logger.info(f"Found {len(all_cves)} CVEs to process")
        
        # Start fresh CSV file for batch processing
        if os.path.exists(csv_file):
            os.remove(csv_file)
        
        # Process all CVEs with progress bar
        for cve in tqdm(sorted(all_cves), desc="Processing CVEs"):
            process_cve(cve, predictor, cve_cwe_mapping, args.output_dir, csv_file, args.debug)
            
        logger.info(f"Completed processing {len(all_cves)} CVEs")
        logger.info(f"Results saved in {args.output_dir}")
        
    else:
        # Process single CVE
        process_cve(args.cve, predictor, cve_cwe_mapping, args.output_dir, csv_file, True)
        
        # Print detailed results for single CVE
        json_file = os.path.join(args.output_dir, 'CVE', f"{args.cve}.json")
        with open(json_file, 'r') as f:
            results = json.load(f)
            
        print("\nCWE Prediction Results")
        print("=" * 50)
        print(f"Target CVE: {results['target_cve']}")
        known_cwe = results['known_cwe'].replace('CWE-', '')
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