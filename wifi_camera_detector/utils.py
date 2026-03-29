# 工具函数模块
import re
import socket
import struct
import subprocess
import platform


def is_valid_ip(ip):
    """验证IP地址是否合法"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)


def get_vendor_name(mac, vendors_dict):
    """根据MAC地址获取厂商名"""
    if not mac or mac == "Unknown":
        return None
    # 提取前3个字节作为MAC前缀
    mac_clean = mac.replace(':', '-').upper()
    parts = mac_clean.split('-')
    if len(parts) >= 3:
        prefix = '-'.join(parts[:3])
        return vendors_dict.get(prefix)
    return None


def format_mac(mac):
    """格式化MAC地址为统一格式 XX-XX-XX-XX-XX-XX"""
    if not mac or mac == "Unknown":
        return "Unknown"
    # 移除所有分隔符，转为大写
    mac_clean = re.sub(r'[^a-fA-F0-9]', '', mac).upper()
    # 每两个字符一组，用-连接
    return '-'.join(mac_clean[i:i+2] for i in range(0, 12, 2))


def risk_level_label(level):
    """风险等级转显示文本"""
    level_map = {
        "critical": "高危",
        "high": "高风险",
        "medium": "中风险",
        "low": "低危",
        "unknown": "未知"
    }
    return level_map.get(level.lower(), level)


def get_local_ip():
    """获取本机IP地址"""
    try:
        # 创建一个UDP套接字
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 连接一个公网地址（不一定要可达）
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip
    except Exception:
        # 备选方案
        try:
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)
        except Exception:
            return "127.0.0.1"


def get_network_range(ip=None):
    """获取网段范围，如 192.168.1.0/24"""
    if not ip:
        ip = get_local_ip()
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return None


def ip_to_int(ip):
    """IP地址转整数"""
    try:
        return struct.unpack('!I', socket.inet_aton(ip))[0]
    except Exception:
        return 0


def int_to_ip(n):
    """整数转IP地址"""
    try:
        return socket.inet_ntoa(struct.pack('!I', n))
    except Exception:
        return "0.0.0.0"


def get_mac_address(ip):
    """获取指定IP的MAC地址"""
    try:
        system = platform.system()
        if system == "Windows":
            # Windows: 使用arp命令
            result = subprocess.run(
                ["arp", "-a", ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            output = result.stdout
            # 解析ARP输出找到MAC地址
            for line in output.split('\n'):
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if re.match(r'^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$', part):
                            return format_mac(part)
        else:
            # Linux/Mac: 使用arp命令
            result = subprocess.run(
                ["arp", ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            output = result.stdout
            # 解析MAC地址
            match = re.search(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', output)
            if match:
                return format_mac(match.group())
    except Exception:
        pass
    return "Unknown"


def ping_host(ip, timeout=1):
    """Ping一个主机检测是否在线"""
    try:
        system = platform.system()
        if system == "Windows":
            result = subprocess.run(
                ["ping", "-n", "1", "-w", str(timeout * 1000), ip],
                capture_output=True,
                timeout=timeout + 2
            )
        else:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout), ip],
                capture_output=True,
                timeout=timeout + 2
            )
        return result.returncode == 0
    except Exception:
        return False
