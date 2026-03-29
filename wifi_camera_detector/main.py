#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi摄像头检测工具
用于检测局域网中的可疑摄像头设备，防止偷拍

作者：Claude Code Assistant
版本：1.0
"""

import sys
import os

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def check_dependencies():
    """检查依赖库是否安装"""
    missing = []

    try:
        import tkinter
    except ImportError:
        missing.append("tkinter")

    try:
        import cv2
    except ImportError:
        missing.append("opencv-python")

    try:
        import scapy
    except ImportError:
        missing.append("scapy")

    return missing


def install_dependencies():
    """安装依赖库"""
    print("正在安装依赖库...")
    import subprocess

    deps = ["opencv-python", "scapy"]
    for dep in deps:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep])
            print(f"[OK] {dep} installed successfully")
        except Exception as e:
            print(f"[FAIL] {dep} installation failed: {e}")


def main():
    """主函数"""
    print("=" * 60)
    print("WiFi Camera Detector v1.0")
    print("=" * 60)
    print()

    # 检查依赖
    missing = check_dependencies()

    if missing:
        print("Missing the following dependencies:")
        for dep in missing:
            print(f"  - {dep}")
        print()

        response = input("Install dependencies automatically? (y/n): ").strip().lower()
        if response == 'y':
            install_dependencies()
            print()
            print("Please restart the program")
            input("Press Enter to exit...")
            return
        else:
            print("Please install dependencies manually and run again")
            input("Press Enter to exit...")
            return

    print("[OK] Dependencies check passed")
    print()

    # 导入模块
    try:
        from scanner import NetworkScanner
        from detector import CameraDetector
        from ui import CameraDetectorUI
    except ImportError as e:
        print(f"Failed to import module: {e}")
        print("Please ensure all Python files are in the same directory")
        input("Press Enter to exit...")
        return

    # 启动GUI
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()

        # 初始化扫描器和检测器 - 优化：增加并发数，减少超时时间
        scanner = NetworkScanner(max_workers=100, timeout=0.5)  # 优化2&3: 更多线程+更短超时
        detector = CameraDetector(max_workers=20, timeout=1)

        # 创建UI
        app = CameraDetectorUI(root, scanner, detector)

        print("[OK] GUI initialized")
        print()
        print("Tips:")
        print("  - Click 'Start Scan' to begin detection")
        print("  - Scanning may take 1-3 minutes, please be patient")
        print("  - High-risk devices will be marked in red")
        print()

        root.mainloop()

    except Exception as e:
        print(f"Failed to start GUI: {e}")
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()
