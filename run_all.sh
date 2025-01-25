#!/bin/sh

python3 extract_similar_cves.py --threshold 70
python3 extract_similar_cves.py --threshold 75
python3 extract_similar_cves.py --threshold 80
python3 extract_similar_cves.py --threshold 85
python3 extract_similar_cves.py --threshold 90
python3 extract_similar_cves.py --threshold 95

python3 multi_threshold_analysis_range.py


python3 scripts/cwe_predictor.py --all