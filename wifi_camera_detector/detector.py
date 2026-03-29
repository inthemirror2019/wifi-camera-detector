# 摄像头检测模块
import socket
import time
import cv2
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import get_mac_address, ping_host
from mac_vendors import MAC_VENDORS, CAMERA_PORTS, RTSP_PATHS, get_risk_level


class CameraDetector:
    """摄像头检测器"""

    def __init__(self, max_workers=10, timeout=2):
        self.max_workers = max_workers
        self.timeout = timeout
        self._stop_flag = threading.Event()

    def stop(self):
        """停止检测"""
        self._stop_flag.set()

    def is_stopped(self):
        """检查是否已停止"""
        return self._stop_flag.is_set()

    def reset(self):
        """重置停止标志"""
        self._stop_flag.clear()

    def identify_vendor(self, mac):
        """根据MAC地址识别厂商"""
        if not mac or mac == "Unknown":
            return None

        # 提取前3个字节（OUI）
        mac_clean = mac.replace(':', '-').upper()
        parts = mac_clean.split('-')
        if len(parts) >= 3:
            prefix = '-'.join(parts[:3])
            return MAC_VENDORS.get(prefix)
        return None

    def check_port(self, ip, port, timeout=None):
        """检查端口是否开放"""
        if timeout is None:
            timeout = self.timeout

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def scan_ports(self, ip, ports=None, progress_callback=None):
        """扫描指定IP的开放端口"""
        if ports is None:
            ports = CAMERA_PORTS

        open_ports = []
        total = len(ports)
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self.check_port, ip, port): port
                for port in ports
            }

            for future in as_completed(future_to_port):
                if self.is_stopped():
                    executor.shutdown(wait=False)
                    break

                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    pass

                completed += 1
                if progress_callback:
                    progress_callback(completed, total)

        return sorted(open_ports)

    def test_rtsp_stream(self, ip, port=554, timeout=5):
        """
        测试RTSP视频流是否可访问
        返回：(是否可访问, 路径)
        """
        # 尝试不同的RTSP路径
        for path in RTSP_PATHS[:10]:  # 只测试前10个常用路径
            if self.is_stopped():
                return False, None

            rtsp_url = f"rtsp://{ip}:{port}{path}"
            try:
                cap = cv2.VideoCapture(rtsp_url)
                cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, timeout * 1000)
                cap.set(cv2.CAP_PROP_READ_TIMEOUT_MSEC, timeout * 1000)

                if cap.isOpened():
                    ret, frame = cap.read()
                    cap.release()
                    if ret:
                        return True, path
                cap.release()
            except Exception:
                pass

        return False, None

    def detect_camera(self, ip, mac=None, scan_ports=True, check_rtsp=True, progress_callback=None):
        """
        综合检测一个IP是否为摄像头
        返回：检测结果字典
        """
        if self.is_stopped():
            return None

        # 如果没有提供MAC，尝试获取
        if not mac:
            mac = get_mac_address(ip)

        # 识别厂商
        vendor = self.identify_vendor(mac)

        # 检测开放端口
        open_ports = []
        if scan_ports:
            open_ports = self.scan_ports(ip, progress_callback=progress_callback)

        # 检测RTSP流
        rtsp_accessible = False
        rtsp_path = None
        if check_rtsp and (554 in open_ports or 555 in open_ports):
            rtsp_accessible, rtsp_path = self.test_rtsp_stream(ip)

        # 判断是否为摄像头
        is_camera = False
        confidence = 0  # 置信度 0-100

        # 1. 厂商匹配
        if vendor:
            confidence += 30
            if any(kw in str(vendor) for kw in ["海康", "大华", "Hikvision", "Dahua", "TP-Link", "萤石", "乔安"]):
                confidence += 20

        # 2. RTSP端口开放
        if 554 in open_ports or 555 in open_ports:
            confidence += 20
            is_camera = True

        # 3. 其他摄像头端口
        camera_port_count = sum(1 for p in open_ports if p in [80, 81, 82, 83, 84, 85, 88, 443, 8000, 8008, 8080, 8081, 8200, 37777])
        if camera_port_count >= 2:
            confidence += 15

        # 4. RTSP流可访问
        if rtsp_accessible:
            confidence = min(100, confidence + 30)
            is_camera = True

        # 判断最终结果
        is_camera = confidence >= 50

        # 计算风险等级
        risk_level, risk_color = self._calculate_risk(
            is_camera, vendor, open_ports, rtsp_accessible, confidence
        )

        return {
            'ip': ip,
            'mac': mac,
            'vendor': vendor,
            'open_ports': open_ports,
            'is_camera': is_camera,
            'confidence': confidence,
            'rtsp_accessible': rtsp_accessible,
            'rtsp_path': rtsp_path,
            'risk_level': risk_level,
            'risk_color': risk_color
        }

    def _calculate_risk(self, is_camera, vendor, open_ports, rtsp_accessible, confidence):
        """计算风险等级"""
        # 高危：确认是摄像头且RTSP可访问
        if is_camera and rtsp_accessible and confidence >= 80:
            return "高危", "red"

        # 高风险：确认是摄像头或RTSP端口开放
        if is_camera or (554 in open_ports and rtsp_accessible):
            return "高风险", "orange"

        # 中风险：有摄像头厂商MAC或开放摄像头相关端口
        if vendor or len([p for p in open_ports if p in [554, 555, 8000, 8008, 8200, 37777]]) > 0:
            return "中风险", "yellow"

        # 低风险：仅在线
        return "低危", "green"


if __name__ == "__main__":
    # 测试代码
    detector = CameraDetector(max_workers=10)

    # 测试本机
    local_ip = get_local_ip()
    print(f"测试检测本机: {local_ip}")

    result = detector.detect_camera(local_ip, scan_ports=True, check_rtsp=False)
    if result:
        print(f"检测结果:")
        print(f"  IP: {result['ip']}")
        print(f"  MAC: {result['mac']}")
        print(f"  厂商: {result['vendor']}")
        print(f"  开放端口: {result['open_ports']}")
        print(f"  是否摄像头: {result['is_camera']}")
        print(f"  置信度: {result['confidence']}%")
        print(f"  风险等级: {result['risk_level']}")
