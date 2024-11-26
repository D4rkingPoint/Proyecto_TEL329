import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

def parse_motes(file_path):
    motes_data = []
    with open(file_path, 'r') as file:
        for line in file:
            # Parse motes log lines based on known format
            if 'ID:' in line:
                parts = line.split()
                time = parts[0]
                mote_id = parts[2]
                message = ' '.join(parts[3:])
                motes_data.append({'Time': time, 'Mote ID': mote_id, 'Message': message})
    return pd.DataFrame(motes_data)

def parse_wireshark(file_path):
    wireshark_data = []
    with open(file_path, 'r') as file:
        for line in file:
            # Parse wireshark log lines based on known format
            parts = line.split('\t')
            if len(parts) >= 4:
                timestamp = parts[0]
                source = parts[1]
                destination = parts[2]
                data = parts[3]
                # Exclude lines where the destination is "-"
                if destination.strip() != "-":
                    wireshark_data.append({'Timestamp': timestamp, 'Source': source, 'Destination': destination, 'Data': data})
    return pd.DataFrame(wireshark_data)

def combine_logs(motes_df, wireshark_df):
    # Combine the dataframes based on nearest timestamps or other common fields if available
    combined_df = pd.concat([motes_df, wireshark_df], axis=1)
    return combined_df

# File paths
motes_file = "motes.txt"
wireshark_file = "wireshark.txt"

# Parse logs
motes_df = parse_motes(motes_file)
wireshark_df = parse_wireshark(wireshark_file)

# Combine logs
combined_df = combine_logs(motes_df, wireshark_df)

# Save to CSV
csv_output_path = "combined_logs_2.csv"
combined_df.to_csv(csv_output_path, index=False)

print(f"Combined logs saved to {csv_output_path}")

#############################################

import pandas as pd
import matplotlib.pyplot as plt

# Load the combined CSV file
file_path = "combined_logs.csv"
data = pd.read_csv(file_path)

# Summarize packet counts between nodes
packet_counts = data.groupby(['Source', 'Destination']).size().reset_index(name='Count')

# Generate a more visually clear bar chart
plt.figure(figsize=(12, 8))
sorted_packet_counts = packet_counts.sort_values(by='Count', ascending=False)
plt.barh(sorted_packet_counts.apply(lambda row: f"{row['Source']} -> {row['Destination']}", axis=1),
         sorted_packet_counts['Count'], color='skyblue')

# Add titles and labels
plt.title("Packet Transmissions Between Nodes - without BlackHole", fontsize=16)
plt.xlabel("Number of Packets", fontsize=12)
plt.ylabel("Node Pairs", fontsize=12)
plt.tight_layout()
plt.grid(axis='x', linestyle='--', alpha=0.7)
plt.show()


#############################################


# Load the data
file_path_no_blackhole = "combined_logs.csv"  # File without blackhole
file_path_with_blackhole = "combined_logs_2.csv"  # File with blackhole

# Load the data
data_no_blackhole = pd.read_csv(file_path_no_blackhole)
data_with_blackhole = pd.read_csv(file_path_with_blackhole)

# Ensure consistent data types for 'Source' and 'Destination'
data_no_blackhole['Source'] = data_no_blackhole['Source'].astype(str)
data_no_blackhole['Destination'] = data_no_blackhole['Destination'].astype(str)
data_with_blackhole['Source'] = data_with_blackhole['Source'].astype(str)
data_with_blackhole['Destination'] = data_with_blackhole['Destination'].astype(str)

# Summarize packet counts
packet_counts_no_blackhole = data_no_blackhole.groupby(['Source', 'Destination']).size().reset_index(name='Count_no_blackhole')
packet_counts_with_blackhole = data_with_blackhole.groupby(['Source', 'Destination']).size().reset_index(name='Count_with_blackhole')

# Merge data to align packet counts
merged_counts = pd.merge(
    packet_counts_no_blackhole,
    packet_counts_with_blackhole,
    on=['Source', 'Destination'],
    how='outer'
)

# Fill NaN with 0 for comparison
merged_counts.fillna(0, inplace=True)

# Add a flag for rows involving node 11
merged_counts['Contains_Node_11'] = merged_counts.apply(
    lambda row: '11' in row['Source'] or '11' in row['Destination'], axis=1
)

# Add a flag for specific Root-Receiver communication
root_receiver_pairs = [('1', '2'), ('1', '3'), ('1', '4'), ('2', '1'), ('3', '1'), ('4', '1')]
merged_counts['Is_Root_Receiver'] = merged_counts.apply(
    lambda row: (row['Source'], row['Destination']) in root_receiver_pairs, axis=1
)

# Create subsets for each plot
df_morados = merged_counts[merged_counts['Contains_Node_11']]
df_root_receiver = merged_counts[merged_counts['Is_Root_Receiver']]
df_other = merged_counts[~merged_counts['Contains_Node_11'] & ~merged_counts['Is_Root_Receiver']]

# Function to calculate and add loss percentages
def add_loss_percentages(ax, df, positions):
    for i, pos in enumerate(positions):
        no_blackhole = df.iloc[i]['Count_no_blackhole']
        with_blackhole = df.iloc[i]['Count_with_blackhole']
        if no_blackhole > 0:
            difference = with_blackhole - no_blackhole
            loss_percentage = (difference / no_blackhole) * 100
            if difference < 0:
                ax.text(pos, max(no_blackhole, with_blackhole) + 2, f"-{abs(loss_percentage):.1f}%", ha='center', fontsize=9, color='black')
            else:
                ax.text(pos, max(no_blackhole, with_blackhole) + 2, f"+{loss_percentage:.1f}%", ha='center', fontsize=9, color='black')
        else:
            ax.text(pos, with_blackhole + 2, "+", ha='center', fontsize=9, color='black')

# Function to calculate and add total percentage legend for morados
def add_total_percentage_legend(ax, df):
    total_data = len(merged_counts)
    morado_data = len(df)
    percentage = (morado_data / total_data) * 100
    ax.legend([f"Las comunicaciones con el nodo malicioso representan el {percentage:.1f}% del total de datos estudiados"], loc='upper right', fontsize=10)

# Function to plot

def plot_combined_bar(subsets, titles, bar_colors, bar_labels):
    fig, axes = plt.subplots(1, 2, figsize=(16, 8), sharey=True)
    for ax, df, title, colors in zip(axes, subsets, titles, bar_colors):
        positions = np.arange(len(df))
        ax.bar(
            positions - 0.2, 
            df['Count_no_blackhole'], 
            width=0.4, 
            color=colors[0], 
            label=bar_labels[0]
        )
        ax.bar(
            positions + 0.2, 
            df['Count_with_blackhole'], 
            width=0.4, 
            color=colors[1], 
            label=bar_labels[1]
        )
        add_loss_percentages(ax, df, positions)
        labels = df.apply(lambda row: f"{row['Source']} -> {row['Destination']}", axis=1)
        ax.set_xticks(positions)
        ax.set_xticklabels(labels, rotation=90, fontsize=10)
        ax.set_title(title, fontsize=14)
        ax.grid(axis='y', linestyle='--', alpha=0.7)

    axes[0].set_ylabel("Number of Packets", fontsize=12)
    plt.legend(loc='upper center', bbox_to_anchor=(-0.1, 1.1), ncol=2, fontsize=12)
    plt.tight_layout()
    plt.show()

def plot_blackhole_only(df, title):
    plt.figure(figsize=(10, 8))
    positions = np.arange(len(df))
    plt.bar(
        positions, 
        df['Count_with_blackhole'], 
        width=0.6, 
        color='purple', 
        label="Con Blackhole"
    )
    labels = df.apply(lambda row: f"{row['Source']} -> {row['Destination']}", axis=1)
    plt.xticks(positions, labels, rotation=90, fontsize=10)
    plt.title(title, fontsize=14)
    plt.ylabel("Number of Packets", fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    ax = plt.gca()
    add_total_percentage_legend(ax, df)
    plt.show()

# Subsets, titles, and colors for the plots
subsets = [df_root_receiver, df_other]
titles = [
    "Comunicación Receiver-Root",
    "Comunicación Sender-Receiver"
]
bar_colors = [
    ['green', 'red'],
    ['blue', 'red']
]
bar_labels = ["Sin Blackhole", "Con Blackhole"]

# Plot combined bar for Root-Receiver and Other Communications
plot_combined_bar(subsets, titles, bar_colors, bar_labels)

# Plot only communications involving Blackhole
plot_blackhole_only(df_morados, "Comunicación nodo malicioso")

#############################################