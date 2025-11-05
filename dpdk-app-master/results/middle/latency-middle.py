import re
import csv
import matplotlib.pyplot as plt

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

# Step 3: Plot the line chart with three lines
packet_numbers = list(range(1, 501))  # Assuming 50 packets for each scenario

plt.figure(figsize=(12, 7))  # Set figure size
plt.plot(packet_numbers, scenario1_latencies, marker="o", linestyle="-", color="b", label="PoT")
plt.plot(packet_numbers, scenario2_latencies, marker="s", linestyle="--", color="r", label="Forwarding or Adding SRH")

# Add labels, title, and legend
plt.xlabel("Packet Number")
plt.ylabel("Latency (µs)")
plt.yscale("log")
plt.title("Latency Over Packet Count for Two Scenarios")
plt.legend()
plt.grid(True)

# Save the chart as an image
plt.savefig("latency_comparison.png", dpi=300, bbox_inches="tight")

# Display the chart
plt.show()