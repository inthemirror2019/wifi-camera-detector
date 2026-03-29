# 网络扫描模块
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import (
    get_local_ip, get_network_range, ip_to_int, int_to_ip,
    get_mac_address, ping_host, is_valid_ip
)


class NetworkScanner:
    """网络扫描器"""

    def __init__(self, max_workers=50, timeout=2):
        self.max_workers = max_workers
        self.timeout = timeout
        self.local_ip = get_local_ip()
        self.network = get_network_range(self.local_ip)
        self._stop_flag = threading.Event()

    def stop(self):
        """停止扫描"""
        self._stop_flag.set()

    def is_stopped(self):
        """检查是否已停止"""
        return self._stop_flag.is_set()

    def reset(self):
        """重置停止标志"""
        self._stop_flag.clear()

    def get_ip_range(self):
        """获取IP范围列表 - 优化：只扫描常用IP段"""
        if not self.network:
            return []

        # 解析 192.168.1.0/24
        base_ip = self.network.split('/')[0]
        parts = base_ip.split('.')

        if len(parts) != 4:
            return []

        ip_list = []

        # 优化1：只扫描常用IP范围（1-50 和 100-150），跳过高段IP
        # 大多数路由器、电脑、手机使用 1-50 的范围
        # 一些IoT设备使用 100-150 的范围
        common_ranges = [
            range(1, 51),    # 1-50: 常见的主路由、电脑、手机
            range(100, 151), # 100-150: 常见的IoT设备、摄像头
        ]

        for ip_range in common_ranges:
            for i in ip_range:
                ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{i}"
                # 跳过本机IP
                if ip != self.local_ip:
                    ip_list.append(ip)

        return ip_list

    def scan_host(self, ip):
        """扫描单个主机"""
        if self.is_stopped():
            return None

        if not is_valid_ip(ip):
            return None

        # 使用Ping检测主机是否存活
        if ping_host(ip, timeout=self.timeout):
            # 获取MAC地址
            mac = get_mac_address(ip)
            return {
                'ip': ip,
                'mac': mac,
                'status': 'online'
            }

        return None

    def scan_network(self, progress_callback=None, result_callback=None):
        """
        扫描整个网络
        :param progress_callback: 进度回调函数(current, total, percent)
        :param result_callback: 结果回调函数(device_info)
        :return: 发现的设备列表
        """
        self.reset()
        ip_list = self.get_ip_range()
        total = len(ip_list)
        results = []
        completed = 0

        if progress_callback:
            progress_callback(0, total, 0)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {executor.submit(self.scan_host, ip): ip for ip in ip_list}

            for future in as_completed(future_to_ip):
                if self.is_stopped():
                    executor.shutdown(wait=False)
                    break

                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        if result_callback:
                            result_callback(result)
                except Exception as e:
                    pass

                completed += 1
                if progress_callback:
                    percent = int((completed / total) * 100)
                    progress_callback(completed, total, percent)

        return results


def check_open_port(ip, port, timeout=2):
    """
    检查指定端口是否开放
    :param ip: IP地址
    :param port: 端口号
    :param timeout: 超时时间（秒）
    :return: 是否开放
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def scan_ports(ip, ports=None, max_workers=10, timeout=2):
    """扫描指定IP的开放端口"""
    if ports is None:
        from mac_vendors import CAMERA_PORTS
        ports = CAMERA_PORTS

    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(check_open_port, ip, port, timeout): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass

    return sorted(open_ports)


if __name__ == "__main__":
    # 测试代码
    scanner = NetworkScanner(max_workers=20, timeout=1)
    print(f"本机IP: {scanner.local_ip}")
    print(f"扫描网段: {scanner.network}")

    def on_progress(current, total, percent):
        print(f"\r扫描进度: {current}/{total} ({percent}%)", end="")

    def on_result(device):
        print(f"\n发现设备: {device['ip']} - {device['mac']}")

    results = scanner.scan_network(on_progress, on_result)
    print(f"\n\n扫描完成，共发现 {len(results)} 个在线设备")
