import os
import subprocess
import time
import random
from datetime import datetime
import threading
import re

# 定义需要测试的端口和次数
ports = range(4034, 4035)
output_dir = 'testversion/packets'

# 创建输出目录
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

def get_timestamp():
    now = datetime.now()
    return now.strftime("%m_%d_%H_%M")  # e.g., '11_25_16_00'

# 定义抓包的函数
def capture_packets(port, run_number, file_size, port_dir):
    capture_file = f"{port_dir}/{file_size}_{run_number}.pcapng"

    url = f"http://tcpdynamics.uk:{port}/{file_size}"
    null_device = 'NUL' if os.name == 'nt' else '/dev/null'
    curl_command = ['curl', '-v', '-4', '-o', null_device, url]

    # 确定网络接口
    if os.name == 'nt':
        # 在Windows上，需要指定接口编号或名称
        interface = '5'  # 请根据实际情况修改
    else:
        interface = 'any'

    # 添加 tshark.exe 的完整路径
    tshark_exe = 'D:/Wireshark/tshark.exe'  # 请根据实际情况修改
    tshark_command = [tshark_exe, '-l', '-i', interface, '-w', capture_file, '-f', f'port {port}']

    tshark_proc = None
    curl_proc = None

    try:
        print(f"tshark command: {' '.join(tshark_command)}")
        tshark_proc = subprocess.Popen(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(5)  # 等待 tshark 启动

        curl_proc = subprocess.Popen(curl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        last_progress_time = time.time()
        progress_timeout = 60  # 无进展的超时时间（秒），可根据需要调整
        total_timeout = 90    # 总超时时间（秒），可根据需要调整

        start_time = time.time()

        # 定义一个线程函数，用于监控 curl 的进度
        def monitor_progress():
            nonlocal last_progress_time
            pattern = re.compile(r'%\s+Total\s+% Received\s+% Xferd')
            while True:
                if curl_proc.poll() is not None:
                    break
                line = curl_proc.stderr.readline()
                if line:
                    line = line.strip()
                    print(f"curl stderr: {line}")
                    if not pattern.match(line):
                        # 更新最后的进度时间
                        last_progress_time = time.time()
                else:
                    time.sleep(1)

        # 启动监控线程
        monitor_thread = threading.Thread(target=monitor_progress)
        monitor_thread.start()

        while True:
            if curl_proc.poll() is not None:
                break

            elapsed_time = time.time() - start_time
            time_since_last_progress = time.time() - last_progress_time

            # 检查是否超过总的超时时间
            if elapsed_time > total_timeout:
                print(f"Total time exceeded {total_timeout} seconds, terminating curl.")
                curl_proc.terminate()
                break

            # 检查是否长时间没有进展
            if time_since_last_progress > progress_timeout:
                print(f"Progress has stalled for {progress_timeout} seconds, terminating curl.")
                curl_proc.terminate()
                break

            time.sleep(1)

        curl_proc.wait()
        monitor_thread.join()

        # 检查 curl 命令是否成功
        if curl_proc.returncode == 0:
            success = True
        else:
            success = False
            print(f"curl command failed with return code {curl_proc.returncode}")

        # 终止 tshark 进程
        time.sleep(10)
        tshark_proc.terminate()
        tshark_proc.wait()

        # 检查捕获文件是否有效
        if os.path.exists(capture_file) and os.path.getsize(capture_file) > 0 and success:
            return True
        else:
            print(f"Capture file {capture_file} does not exist or is empty.")
            # 重命名捕获文件，添加失败标志
            if os.path.exists(capture_file):
                failed_capture_file = f"{capture_file}_failed.pcapng"
                os.rename(capture_file, failed_capture_file)
            return False

    except Exception as e:
        print(f"Error during capture or curl: {e}")
        if curl_proc is not None:
            curl_proc.terminate()
            curl_proc.wait()
        if tshark_proc is not None:
            tshark_proc.terminate()
            tshark_proc.wait()
        # 重命名捕获文件，添加失败标志
        if os.path.exists(capture_file):
            failed_capture_file = f"{capture_file}_failed.pcapng"
            os.rename(capture_file, failed_capture_file)
        return False

def main():
    for port in ports:
        print(f"Testing port {port}...")
        timestamp = get_timestamp()
        port_dir = f"{output_dir}/{port}_{timestamp}"
        if not os.path.exists(port_dir):
            os.makedirs(port_dir)

        # 初始化计数器
        timeouts = 0
        successes = 0
        run_number = 0
        initial_file_size = '256K'

        # 初始抓取 256K 包，直到成功抓取 10 次或超时超过一半
        file_size = initial_file_size
        while successes < 10:
            run_number += 1
            print(f"  Run {run_number} with size {file_size}...")
            success = capture_packets(port, run_number, file_size, port_dir)
            if success:
                successes += 1
            else:
                timeouts += 1

            # 添加随机时间间隔
            random_delay = random.randint(1, 10)
            print(f"Waiting for {random_delay} seconds before the next capture...")
            time.sleep(random_delay)

            # 如果超时次数超过运行次数的一半，切换到 64K
            if timeouts > run_number / 2:
                print(f"Port {port}: Timeouts exceed half of runs ({timeouts}/{run_number}). Switching to 64K packets.")
                break

        if successes >= 10:
            print(f"Port {port}: Sufficient successful captures with size {file_size}.")
            continue

        # 切换到抓取 64K 包，直到成功抓取 40 次
        file_size = '64K'
        successes = 0
        timeouts = 0
        run_number = 0
        while successes < 20:
            run_number += 1
            print(f"  Run {run_number} with size {file_size}...")
            success = capture_packets(port, run_number, file_size, port_dir)
            if success:
                successes += 1
            else:
                timeouts += 1

            # 添加随机时间间隔
            random_delay = random.randint(1, 5)
            print(f"Waiting for {random_delay} seconds before the next capture...")
            time.sleep(random_delay)

            # 可根据需要添加超时判断逻辑

        print(f"Port {port}: Completed capturing 40 successful captures of size {file_size}.")

if __name__ == '__main__':
    main()
