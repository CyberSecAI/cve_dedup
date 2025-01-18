import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
import gzip
from pathlib import Path
import numpy as np

def analyze_similarity_groups(similarity_file: str, threshold: int = 90) -> pd.DataFrame:
    """
    Analyze CWE consistency within similarity groups.
    Returns a DataFrame with analysis results.
    """
    # Load similarity groups
    with gzip.open(similarity_file, 'rt') as f:
        data = json.load(f)
    
    groups_analysis = []
    for group in data['groups']:
        # Get all CVEs in group
        base_cve = group['base_cve']
        similar_cves = [s['cve'] for s in group['similar_cves']]
        all_cves = [base_cve] + similar_cves
        
        group_info = {
            'group_size': len(all_cves),
            'cves': all_cves,
            'base_cve': base_cve,
            'similarity_threshold': threshold
        }
        groups_analysis.append(group_info)
    
    return pd.DataFrame(groups_analysis)

def create_cwe_consistency_plots(groups_df: pd.DataFrame, cve_cwe_df: pd.DataFrame):
    """Create visualizations for CWE consistency analysis."""
    # Merge CWE information with groups
    cve_to_cwe = dict(zip(cve_cwe_df['CVE'], cve_cwe_df['CWE']))
    
    # Calculate CWE consistency for each group
    group_stats = []
    for _, group in groups_df.iterrows():
        cwes = [cve_to_cwe.get(cve, 'Unknown') for cve in group['cves']]
        unique_cwes = len(set(cwes))
        
        group_stats.append({
            'group_size': group['group_size'],
            'unique_cwes': unique_cwes,
            'is_consistent': unique_cwes == 1,
            'cwes': cwes
        })
    
    stats_df = pd.DataFrame(group_stats)
    
    # Create figure with subplots
    fig = plt.figure(figsize=(20, 15))
    
    # 1. Consistency Ratio Plot (top left)
    ax1 = plt.subplot2grid((2, 2), (0, 0))
    consistency_ratio = (stats_df['is_consistent'].sum() / len(stats_df)) * 100
    
    colors = ['#2ecc71', '#e74c3c']
    sizes = [consistency_ratio, 100 - consistency_ratio]
    labels = [f'Consistent\n({consistency_ratio:.1f}%)', 
              f'Inconsistent\n({100-consistency_ratio:.1f}%)']
    
    ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
            startangle=90, wedgeprops=dict(width=0.5))
    ax1.set_title('CWE Consistency in Similarity Groups', pad=20)
    
    # 2. Group Size vs CWE Count (top right)
    ax2 = plt.subplot2grid((2, 2), (0, 1))
    
    # Add some jitter to avoid overlapping points
    jitter = np.random.normal(0, 0.1, len(stats_df))
    scatter = ax2.scatter(stats_df['group_size'] + jitter, 
                         stats_df['unique_cwes'],
                         alpha=0.5, c=stats_df['is_consistent'].map({True: '#2ecc71', False: '#e74c3c'}))
    
    ax2.set_xlabel('Group Size')
    ax2.set_ylabel('Number of Unique CWEs')
    ax2.set_title('Group Size vs Number of Unique CWEs')
    ax2.grid(True, alpha=0.3)
    
    # 3. Consistency by Group Size (bottom left)
    ax3 = plt.subplot2grid((2, 2), (1, 0))
    
    size_consistency = stats_df.groupby('group_size')['is_consistent'].mean() * 100
    size_consistency.plot(kind='bar', color='#3498db')
    ax3.set_xlabel('Group Size')
    ax3.set_ylabel('Consistency Percentage')
    ax3.set_title('CWE Consistency by Group Size')
    ax3.grid(True, alpha=0.3)
    
    # 4. Distribution of Number of CWEs (bottom right)
    ax4 = plt.subplot2grid((2, 2), (1, 1))
    
    sns.histplot(data=stats_df, x='unique_cwes', bins=20, color='#9b59b6', ax=ax4)
    ax4.set_xlabel('Number of Unique CWEs in Group')
    ax4.set_ylabel('Count')
    ax4.set_title('Distribution of Unique CWEs per Group')
    ax4.grid(True, alpha=0.3)
    
    # Add summary statistics
    summary = f"""
    Summary Statistics:
    Total Groups: {len(stats_df)}
    Consistent Groups: {stats_df['is_consistent'].sum()}
    Average Unique CWEs per Group: {stats_df['unique_cwes'].mean():.2f}
    Max Unique CWEs in a Group: {stats_df['unique_cwes'].max()}
    """
    
    fig.text(0.02, 0.02, summary, fontsize=10,
             bbox=dict(facecolor='white', alpha=0.8))
    
    plt.tight_layout()
    return fig

def main():
    # Load your data
    similarity_file = 'analysis_results/similarity_groups_90.json.gz'
    cve_cwe_df = pd.read_csv('data_in/CVSSData.csv.gz', compression='gzip')
    
    # Analyze groups
    groups_df = analyze_similarity_groups(similarity_file)
    
    # Create plots
    fig = create_cwe_consistency_plots(groups_df, cve_cwe_df)
    
    # Save plot
    plt.savefig('images/cwe_consistency_analysis.png', dpi=300, bbox_inches='tight')
    print("Analysis plots saved to images/cwe_consistency_analysis.png")

if __name__ == "__main__":
    main()