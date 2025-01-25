import pandas as pd
import os as os
import seaborn as sns
import matplotlib.pyplot as plt
import plotly.express as px
import numpy as np

def prepare_data(file_path):
    """
    Prepare the CVE data for visualization.
    """
    # Read the CSV data
    df = pd.read_csv(file_path)
    
    # Create confidence bins
    df['confidence_bin'] = pd.cut(
        df['confidence'],
        bins=[0, 0.2, 0.4, 0.6, 0.8, 1.0],
        labels=['0.0-0.2', '0.2-0.4', '0.4-0.6', '0.6-0.8', '0.8-1.0']
    )
    
    # Clean up CWE values (remove brackets and quotes)
    df['cwe'] = df['cwe'].str.strip("[]'")
    
    # Create pivot table for heatmap
    pivot_df = df.pivot_table(
        values='count',
        index='confidence_bin',
        columns='threshold',
        aggfunc='sum',
        fill_value=0
    )
    
    return df, pivot_df

def create_seaborn_heatmap(pivot_df, output_file=None):
    """
    Create and save a heatmap using Seaborn.
    """
    plt.figure(figsize=(12, 8))
    
    # Create heatmap
    sns.heatmap(
        pivot_df,
        annot=True,  # Show values in cells
        fmt='g',     # Format as general number
        cmap='YlOrRd',  # Yellow to Orange to Red colormap
        cbar_kws={'label': 'Count'},
        square=True
    )
    
    plt.title('CVE Distribution by Threshold and Confidence')
    plt.xlabel('Threshold')
    plt.ylabel('Confidence Range')
    
    # Rotate x-axis labels for better readability
    plt.xticks(rotation=0)
    plt.yticks(rotation=0)
    
    if output_file:
        plt.savefig(output_file, bbox_inches='tight', dpi=300)
        plt.close()
    else:
        plt.show()

def create_plotly_heatmap(pivot_df, output_file=None):
    """
    Create and save a heatmap using Plotly.
    """
    fig = px.imshow(
        pivot_df,
        labels=dict(
            x="Threshold",
            y="Confidence Range",
            color="Count"
        ),
        title='CVE Distribution by Threshold and Confidence',
        color_continuous_scale='YlOrRd'
    )
    
    # Update layout for better readability
    fig.update_layout(
        width=800,
        height=600,
        xaxis_title="Threshold",
        yaxis_title="Confidence Range",
        title_x=0.5,
    )
    
    # Add value annotations
    fig.update_traces(text=pivot_df.values, texttemplate="%{text}")
    
    if output_file:
        fig.write_html(output_file)
    else:
        fig.show()

def create_cwe_specific_heatmaps(df, output_dir=None):
    """
    Create separate heatmaps for each CWE.
    """
    for cwe in df['cwe'].unique():
        # Filter data for specific CWE
        cwe_df = df[df['cwe'] == cwe]
        
        # Create pivot table
        pivot_df = cwe_df.pivot_table(
            values='count',
            index='confidence_bin',
            columns='threshold',
            aggfunc='sum',
            fill_value=0
        )
        
        # Create both visualizations
        if output_dir:
            seaborn_file = f"{output_dir}/seaborn_heatmap_CWE_{cwe}.png"
            plotly_file = f"{output_dir}/plotly_heatmap_CWE_{cwe}.html"
            create_seaborn_heatmap(pivot_df, seaborn_file)
            create_plotly_heatmap(pivot_df, plotly_file)
        else:
            create_seaborn_heatmap(pivot_df)
            create_plotly_heatmap(pivot_df)

def main():
    # File paths
    input_file = "data_out/CVE_similarity/cve_similarity.csv"  # Your input CSV file
    output_dir = "heatmap_outputs"
    
    # Create output directory if it doesn't exist
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    # Prepare data
    df, pivot_df = prepare_data(input_file)
    
    # Create overall heatmaps
    create_seaborn_heatmap(pivot_df, f"{output_dir}/seaborn_heatmap_overall.png")
    create_plotly_heatmap(pivot_df, f"{output_dir}/plotly_heatmap_overall.html")
    
    # Create CWE-specific heatmaps
    create_cwe_specific_heatmaps(df, output_dir)

if __name__ == "__main__":
    main()