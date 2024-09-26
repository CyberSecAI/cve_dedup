# Overview
Deduplicate NVD CVE Descriptions

1. Input: 
   1. CVSSData.csv.gz
2. Output: 
   1. cleaned_optimized_fuzzy_deduplicated_file.csv.gz: deduplicated CVEs
   2. removed_duplicates.csv.gz: the duplicate CVEs
   3. duplicate_info.json.gz: the groups of duplicate CVEs to see group size etc...