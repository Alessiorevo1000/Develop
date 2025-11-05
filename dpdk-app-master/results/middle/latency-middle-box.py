import re
import csv
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

# Function to extract latencies from a log file
def extract_latencies(log_file):
    with open(log_file, "r") as file:
        log_content = file.read()
    latency_pattern = r"Latency: (\d+\.\d+) µs"
    latencies = [float(latency) for latency in re.findall(latency_pattern, log_content)]
    return latencies

# Step 1: Extract latencies from all three log files
scenario1_latencies = extract_latencies("scenario1_log.txt")
scenario2_latencies = extract_latencies("scenario2_log.txt")


# Step 2: Save latencies to CSV files (optional)
def save_latencies_to_csv(latencies, csv_file):
    with open(csv_file, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Packet Number", "Latency (µs)"])
        for i, latency in enumerate(latencies, start=1):
            writer.writerow([i, latency])

save_latencies_to_csv(scenario1_latencies, "scenario1_latencies.csv")
save_latencies_to_csv(scenario2_latencies, "scenario2_latencies.csv")


# Step 3: Combine latencies into a single DataFrame for box plot
data = pd.DataFrame({
    "Scenario": ["PoT"] * len(scenario1_latencies) + ["Simple Forwarding"] * len(scenario2_latencies),
    "Latency (µs)": scenario1_latencies + scenario2_latencies 
})

# Step 4: Create box plot
plt.figure(figsize=(10, 6))
sns.boxplot(x="Scenario", y="Latency (µs)", data=data, palette="Set2")
plt.title("Latency Distribution Across Scenarios (Middle Node)")
plt.xlabel("Scenario")
plt.ylabel("Latency (µs)")
plt.yscale("log")
plt.grid(True)

# Save the chart as an image
plt.savefig("latency_boxplot.png", dpi=300, bbox_inches="tight")

# Display the chart
plt.show()