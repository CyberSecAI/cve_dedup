import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
import gzip
from collections import defaultdict
import numpy as np

def analyze_group_consistency(similarity_file: str, cve_cwe_df: pd.DataFrame):
    """
    Analyze and visualize CWE consistency within similarity groups.
    """
    # Create CVE to CWE mapping
    cve_to_cwe = dict(zip(cve_cwe_df['CVE'], cve_cwe_df['CWE']))
    
    # Load similarity groups
    with gzip.open(similarity_file, 'rt') as f:
        data = json.load(f)
    
    # Analyze each group
    group_stats = []
    for group in data['groups']:
        base_cve = group['base_cve']
        similar_cves = [s['cve'] for s in group['similar_cves']]
        all_cves = [base_cve] + similar_cves
        
        # Get CWEs for each CVE in group
        cwe_counts = defaultdict(int)
        valid_cves = 0
        for cve in all_cves:
            if cve in cve_to_cwe:
                cwes = cve_to_cwe[cve].split('|')
                valid_cves += 1
                for cwe in cwes:
                    cwe_counts[cwe] += 1
        
        if valid_cves > 0:
            # Calculate consistency metrics
            total_cwes = sum(cwe_counts.values())
            primary_cwe = max(cwe_counts.items(), key=lambda x: x[1])[0]
            primary_cwe_count = cwe_counts[primary_cwe]
            consistency_ratio = primary_cwe_count / valid_cves
            
            group_stats.append({
                'group_size': len(all_cves),
                'unique_cwes': len(cwe_counts),
                'primary_cwe': primary_cwe,
                'consistency_ratio': consistency_ratio,
                'primary_cwe_count': primary_cwe_count,
                'total_cwes': total_cwes
            })
    
    # Create figure with subplots
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(20, 15))
    
    # Convert to DataFrame for easier plotting
    stats_df = pd.DataFrame(group_stats)
    
    # 1. Distribution of Consistency Ratios
    sns.histplot(data=stats_df, x='consistency_ratio', bins=20, ax=ax1)
    ax1.set_title('Distribution of CWE Consistency Ratios\nWithin Similarity Groups')
    ax1.set_xlabel('Consistency Ratio (Proportion of CVEs sharing primary CWE)')
    ax1.set_ylabel('Number of Groups')
    ax1.axvline(stats_df['consistency_ratio'].mean(), color='red', linestyle='--', 
                label=f'Mean: {stats_df["consistency_ratio"].mean():.2f}')
    ax1.legend()
    
    # 2. Group Size vs Consistency
    group_size_consistency = stats_df.groupby('group_size')['consistency_ratio'].agg(['mean', 'count']).reset_index()
    scatter = ax2.scatter(group_size_consistency['group_size'], 
                         group_size_consistency['mean'],
                         s=group_size_consistency['count'] * 20,  # Size based on count
                         alpha=0.6)
    ax2.set_title('CWE Consistency by Group Size')
    ax2.set_xlabel('Group Size')
    ax2.set_ylabel('Average Consistency Ratio')
    ax2.grid(True, alpha=0.3)
    
    # Add size legend
    sizes = [10, 50, 100]
    legend_elements = [plt.scatter([], [], s=s*20, c='blue', alpha=0.6, 
                                 label=f'{s} groups') for s in sizes]
    ax2.legend(handles=legend_elements, title='Number of Groups')
    
    # 3. CWE Distribution in Consistent vs Inconsistent Groups
    consistency_threshold = 0.8
    consistent_groups = stats_df[stats_df['consistency_ratio'] >= consistency_threshold]
    inconsistent_groups = stats_df[stats_df['consistency_ratio'] < consistency_threshold]
    
    labels = ['Fully Consistent\n(≥80%)', 'Inconsistent\n(<80%)']
    sizes = [len(consistent_groups), len(inconsistent_groups)]
    colors = ['#2ecc71', '#e74c3c']
    ax3.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
            startangle=90)
    ax3.set_title('Proportion of Consistent vs Inconsistent Groups')
    
    # 4. Number of Unique CWEs per Group
    sns.boxplot(data=stats_df, x='group_size', y='unique_cwes', ax=ax4)
    ax4.set_title('Number of Unique CWEs by Group Size')
    ax4.set_xlabel('Group Size')
    ax4.set_ylabel('Number of Unique CWEs')
    
    # Add summary statistics
    summary = (f"Total Groups Analyzed: {len(stats_df)}\n"
              f"Average Consistency Ratio: {stats_df['consistency_ratio'].mean():.2f}\n"
              f"Median Consistency Ratio: {stats_df['consistency_ratio'].median():.2f}\n"
              f"Groups with ≥80% Consistency: {(len(consistent_groups)/len(stats_df))*100:.1f}%\n"
              f"Average Unique CWEs per Group: {stats_df['unique_cwes'].mean():.2f}")
    
    plt.figtext(0.02, 0.02, summary, fontsize=10, 
                bbox=dict(facecolor='white', alpha=0.8))
    
    plt.tight_layout()
    return fig

def main():
    # Load data
    similarity_file = 'analysis_results/similarity_groups_90.json.gz'
    cve_cwe_df = pd.read_csv('data_in/CVSSData.csv.gz', compression='gzip')
    
    # Create visualization
    fig = analyze_group_consistency(similarity_file, cve_cwe_df)
    
    # Save plot
    plt.savefig('images/cwe_group_consistency.png', dpi=300, bbox_inches='tight')
    print("Analysis plots saved to images/cwe_group_consistency.png")

if __name__ == "__main__":
    main()