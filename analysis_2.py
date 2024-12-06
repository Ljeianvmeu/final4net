import os
import pyshark
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import json
import matplotlib
from datetime import datetime, timedelta

# Define ports and output directories
ports = range(4030, 4040)
output_dir = 'testversion/packets'
analysis_dir = 'results_2'

# Create analysis result directories
if not os.path.exists(analysis_dir):
    os.makedirs(analysis_dir)
throughput_dir = os.path.join(analysis_dir, 'throughput')
if not os.path.exists(throughput_dir):
    os.makedirs(throughput_dir)
rtt_dir = os.path.join(analysis_dir, 'rtt')
if not os.path.exists(rtt_dir):
    os.makedirs(rtt_dir)
combined_dir = os.path.join(analysis_dir, 'combined')
if not os.path.exists(combined_dir):
    os.makedirs(combined_dir)
success_ratio_dir = os.path.join(analysis_dir, 'fail_ratio')
if not os.path.exists(success_ratio_dir):
    os.makedirs(success_ratio_dir)

# Function to analyze capture files
def analyze_packets(capture_file, tshark_exe, port):
    try:
        cap = pyshark.FileCapture(
            capture_file,
            display_filter='tcp.port == {}'.format(port),
            keep_packets=False,
            override_prefs={'tcp.analyze_sequence_numbers': 'TRUE'},
            tshark_path=tshark_exe
        )

        packets_info = []

        for packet in cap:
            try:
                tcp_layer = packet.tcp

                packet_info = {
                    'timestamp': float(packet.sniff_timestamp),
                    'source_ip': packet.ip.src,
                    'dest_ip': packet.ip.dst,
                    'source_port': int(tcp_layer.srcport),
                    'dest_port': int(tcp_layer.dstport),
                    'seq_num': int(tcp_layer.seq),
                    'ack_num': int(tcp_layer.ack),
                    'flags': tcp_layer.flags,
                    'length': int(packet.length)
                }

                # Mark retransmissions and out-of-order packets
                packet_info['retransmission'] = hasattr(tcp_layer, 'analysis_retransmission')
                packet_info['out_of_order'] = hasattr(tcp_layer, 'analysis_out_of_order')

                # Get RTT
                if hasattr(tcp_layer, 'analysis_ack_rtt'):
                    packet_info['rtt'] = float(tcp_layer.analysis_ack_rtt)
                else:
                    packet_info['rtt'] = None

                packets_info.append(packet_info)
            except AttributeError:
                # Skip incomplete TCP packets
                continue
            except Exception:
                # Skip other possible exceptions
                continue

        cap.close()
        return packets_info

    except Exception as e:
        print(f"Error analyzing {capture_file}: {e}")
        return None

def main():
    tshark_exe = "D:/Wireshark/tshark.exe"  # Please modify according to your situation

    # Store data for each port
    port_data = {}

    # Define list of file sizes
    file_sizes = ['256K', '64K', '16K']

    # Iterate through ports
    for port in ports:
        print(f"Processing data for port {port}...")

        # Initialize port data dictionary
        port_data[port] = {}
        for file_size in file_sizes:
            port_data[port][file_size] = {'files': [], 'successes': 0, 'runs': 0}

        # Traverse 'packets' directory to find data for the corresponding port
        for dirpath, dirnames, filenames in os.walk(output_dir):
            dir_parts = os.path.basename(dirpath).split('_')
            if len(dir_parts) >= 1 and dir_parts[0] == str(port):
                for filename in filenames:
                    if filename.endswith('.pcapng'):
                        capture_file = os.path.join(dirpath, filename)
                        file_parts = filename.replace('.pcapng', '').split('_')
                        if len(file_parts) >= 2:
                            file_size = file_parts[0]
                            if file_size in file_sizes:
                                port_data[port][file_size]['runs'] += 1
                                if 'timeout' in filename or 'failed' in filename:
                                    # This is a timeout or failed file, count towards runs but not successes
                                    continue
                                else:
                                    # Successful capture file
                                    port_data[port][file_size]['files'].append(capture_file)
                                    port_data[port][file_size]['successes'] += 1

        # Determine which file size data to use for analysis
        selected_file_size = None
        for file_size in file_sizes:
            runs = port_data[port][file_size]['runs']
            successes = port_data[port][file_size]['successes']
            if runs > 0 and (successes > (runs + 1) / 2 or successes >= 20):
                selected_file_size = file_size
                print(f"Port {port}: Using data size {file_size} for analysis (Successes: {successes}/{runs}).")
                break
        if not selected_file_size:
            print(f"Port {port}: No sufficient successful data found for analysis.")
            continue

        # Analyze data of the selected file size
        packets_info = []
        cumulative_time = 0  # Cumulative time for continuous captures

        # Ensure files are processed in order
        sorted_files = sorted(port_data[port][selected_file_size]['files'], key=lambda x: os.path.basename(x))

        for capture_file in sorted_files:
            print(f"Analyzing {capture_file} for port {port}...")
            result = analyze_packets(capture_file, tshark_exe, port)
            if result:
                # Get min and max timestamps of current pcapng file
                current_start_time = min(packet['timestamp'] for packet in result)
                current_end_time = max(packet['timestamp'] for packet in result)
                current_duration = current_end_time - current_start_time

                # Calculate relative timestamps for each packet
                for packet in result:
                    packet['relative_timestamp'] = cumulative_time + (packet['timestamp'] - current_start_time)

                # Update cumulative time without adding fixed interval
                cumulative_time += current_duration

                packets_info.extend(result)

        if not packets_info:
            print(f"No data for port {port}. Skipping analysis for this port.")
            continue

        # Create DataFrame and perform analysis
        df = pd.DataFrame(packets_info)

        # Use relative time and convert to Timedelta
        df['timestamp'] = pd.to_timedelta(df['relative_timestamp'], unit='s')

        # Set index to 'timestamp'
        df.set_index('timestamp', inplace=True)

        # **Throughput Calculation**
        # Distinguish between valid data and retransmissions/out-of-order data
        df_valid = df[~df['retransmission'] & ~df['out_of_order']]
        df_retrans = df[df['retransmission'] | df['out_of_order']]

        # Calculate throughput, window of 1 second, fill missing with 0
        throughput = df_valid['length'].resample('1s').sum().fillna(0)

        # Linear interpolation to fill missing values
        throughput = throughput.interpolate(method='linear')

        # Smooth throughput with moving average (window size 5, min periods 1)
        throughput_smoothed = throughput.rolling(window=5, min_periods=1).mean()

        # **RTT Calculation**
        if 'rtt' in df.columns and df['rtt'].notna().any():
            rtt = df['rtt'].resample('1s').mean().interpolate(method='linear')  # Linear interpolation

        # **Throughput and RTT Combined Plot**
        plt.figure(figsize=(10, 6))
        plt.plot(throughput_smoothed.index, throughput_smoothed.values, label='Throughput (bytes/sec)', color='red')
        plt.xlabel('Time')
        plt.ylabel('Throughput (bytes/sec)', color='red')
        plt.tick_params(axis='y', labelcolor='red')

        if 'rtt' in df.columns and df['rtt'].notna().any():
            ax2 = plt.twinx()
            ax2.plot(rtt.index, rtt.values, label='RTT (sec)', color='green')
            ax2.set_ylabel('RTT (sec)', color='green')
            ax2.tick_params(axis='y', labelcolor='green')

            plt.title(f'Port {port} Throughput and RTT over Time')
            plt.savefig(os.path.join(combined_dir, f'throughput_rtt_port_{port}.png'))
            plt.close()
            print(f"Port {port} throughput and RTT combined plot saved as 'throughput_rtt_port_{port}.png'")
        else:
            plt.title(f'Port {port} Throughput over Time')
            plt.savefig(os.path.join(combined_dir, f'throughput_port_{port}.png'))
            plt.close()
            print(f"Port {port} throughput plot saved as 'throughput_port_{port}.png'")

        # **Throughput Over Time Plot**
        plt.figure(figsize=(10, 6))
        plt.plot(throughput_smoothed.index, throughput_smoothed.values, label='Throughput (bytes/sec)', color='red')
        plt.xlabel('Time')
        plt.ylabel('Throughput (bytes/sec)')
        plt.title(f'Port {port} Throughput over Time')
        plt.savefig(os.path.join(throughput_dir, f'throughput_port_{port}.png'))
        plt.close()
        print(f"Port {port} throughput plot saved as 'throughput_port_{port}.png'")

        # **RTT Over Time Plot**
        if 'rtt' in df.columns and df['rtt'].notna().any():
            plt.figure(figsize=(10, 6))
            plt.plot(rtt.index, rtt, label='RTT (sec)', color='green')
            plt.xlabel('Time')
            plt.ylabel('RTT (sec)')
            plt.title(f'Port {port} RTT over Time')
            plt.savefig(os.path.join(rtt_dir, f'rtt_port_{port}.png'))
            plt.close()
            print(f"Port {port} RTT plot saved as 'rtt_port_{port}.png'")

        # **Calculate Average Throughput**
        avg_throughput = throughput_smoothed.mean()
        port_data[port]['average_throughput'] = avg_throughput

        # **Retransmissions**
        retransmissions = df_retrans
        avg_retransmissions = len(retransmissions) / len(df) if len(df) > 0 else 0
        port_data[port]['average_retransmissions'] = avg_retransmissions

        # **Calculate Average RTT**
        if 'rtt' in df.columns and df['rtt'].notna().any():
            avg_rtt = rtt.mean()
            port_data[port]['average_rtt'] = avg_rtt
        else:
            port_data[port]['average_rtt'] = None

        # **Calculate Actual Loss Rate**
        # Method 1: Based on sequence and acknowledgment numbers
        sent_seq_nums = set(df['seq_num'])
        min_seq_num = df['seq_num'].min()
        acked_seq_nums = set()
        for ack in df['ack_num']:
            if ack > min_seq_num:
                acked_seq_nums.update(range(min_seq_num, ack))
        lost_seq_nums = sent_seq_nums - acked_seq_nums
        loss_rate_seq_ack = (len(lost_seq_nums) / len(sent_seq_nums)) * 100 if len(sent_seq_nums) > 0 else 0

        # Method 2: Based on retransmissions
        loss_rate_retrans = (len(retransmissions) / len(df)) * 100 if len(df) > 0 else 0

        # Method 3: Combined sequence/ack and retransmissions (recommended)
        loss_rate_combined = max(loss_rate_seq_ack, loss_rate_retrans)

        # Store actual loss rates
        port_data[port]['actual_loss_rate_seq_ack'] = loss_rate_seq_ack
        port_data[port]['actual_loss_rate_retrans'] = loss_rate_retrans
        port_data[port]['actual_loss_rate_combined'] = loss_rate_combined

        print(
            f"Port {port} - Loss Rate (Seq/Ack): {loss_rate_seq_ack:.2f}%, Loss Rate (Retrans): {loss_rate_retrans:.2f}%, Combined Loss Rate: {loss_rate_combined:.2f}%")

        # Store selected file size for plotting
        port_data[port]['selected_file_size'] = selected_file_size

    # **Calculate the ratio of failed captures to total files per port and plot a line chart**
    fail_ratios = {}
    for port in ports:
        total_runs = 0
        total_successes = 0
        for file_size in file_sizes:
            total_runs += port_data[port][file_size]['runs']
            total_successes += port_data[port][file_size]['successes']
        ratio = 100 * (1 - total_successes / total_runs) if total_runs > 0 else 0
        fail_ratios[port] = ratio

    plt.figure(figsize=(10, 6))
    ports_list = sorted(fail_ratios.keys())
    ratios = [fail_ratios[port] for port in ports_list]
    plt.plot(ports_list, ratios, marker='o', linestyle='-')
    plt.xlabel('Port Number')
    plt.ylabel('Capture Failure Ratio (%)')
    plt.title('Capture Failure Ratio per Port (%)')
    plt.ylim(0, 100)  # Ratio between 0 and 100
    plt.grid(True)
    plt.savefig(os.path.join(success_ratio_dir, 'fail_ratio_per_port.png'))
    plt.close()
    print("Capture failure ratio per port plot saved as 'fail_ratio_per_port.png'")

    # **Packet Loss Rate Comparison Plot**
    # Configured loss rates
    configured_loss_rate_per_port = {port: (port - 4030) * 5 for port in ports}  # Known relationship

    # Actual loss rates (using method 3: combined sequence/ack and retransmissions)
    actual_loss_rate_combined_per_port = {port: port_data[port]['actual_loss_rate_combined'] for port in ports if
                                          'actual_loss_rate_combined' in port_data[port]}

    plt.figure(figsize=(10, 6))
    ports_list = sorted(actual_loss_rate_combined_per_port.keys())
    actual_loss_rates = [actual_loss_rate_combined_per_port[port] for port in ports_list]
    configured_loss_rates = [configured_loss_rate_per_port[port] for port in ports_list]

    plt.plot(ports_list, configured_loss_rates, label='Configured Packet Loss Rate', marker='o')
    plt.plot(ports_list, actual_loss_rates, label='Actual Packet Loss Rate', marker='x')
    plt.xlabel('Port Number')
    plt.ylabel('Packet Loss Rate (%)')
    plt.title('Comparison of Configured and Actual Packet Loss Rates')
    plt.legend()
    plt.savefig(os.path.join(analysis_dir, 'packet_loss_rate_comparison.png'))
    plt.close()
    print("Packet loss rate comparison plot saved as 'packet_loss_rate_comparison.png'")

    # **Save analysis results_2 as JSON file**
    analysis_results = {}
    for port in ports:
        analysis_results[port] = {
            'selected_file_size': port_data[port].get('selected_file_size', None),
            'average_throughput': port_data[port].get('average_throughput', None),
            'average_retransmissions': port_data[port].get('average_retransmissions', None),
            'average_rtt': port_data[port].get('average_rtt', None),
            'configured_loss_rate': configured_loss_rate_per_port.get(port, None),
            'actual_loss_rate_seq_ack': port_data[port].get('actual_loss_rate_seq_ack', None),
            'actual_loss_rate_retrans': port_data[port].get('actual_loss_rate_retrans', None),
            'actual_loss_rate_combined': port_data[port].get('actual_loss_rate_combined', None)
        }

    with open(os.path.join(analysis_dir, 'analysis_results.json'), 'w', encoding='utf-8') as f:
        json.dump(analysis_results, f, indent=4, ensure_ascii=False)
    print("Analysis results_2 saved as 'analysis_results.json'")

if __name__ == '__main__':
    main()
