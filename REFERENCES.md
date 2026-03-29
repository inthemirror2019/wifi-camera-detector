# 参考项目列表

本文档收集了 GitHub 上类似的开源 WiFi 摄像头检测工具，供参考和学习。

---

## 1. RogueVision ⭐ 推荐

- **作者**: `bdonz94`
- **地址**: https://github.com/bdonz94/rogue-vision
- **功能**: 专门针对酒店和场馆网络的隐藏摄像头检测
- **特点**:
  - 结合 ARP 扫描、ONVIF 多播、mDNS 发现
  - MAC 厂商查找、HTTP/RTSP 指纹
  - 可疑评分系统
  - GUI 界面，支持房间映射
  - 设备基线、证据导出

---

## 2. AirSafe

- **作者**: `YourHacktivist`
- **地址**: https://github.com/YourHacktivist/AirSafe
- **功能**: Airbnb 隐藏摄像头检测器
- **特点**:
  - 扫描本地网络
  - 识别可疑设备（IP 摄像头、DVR 等 IoT 设备）
  - 帮助旅行者保护隐私

---

## 3. Network-Scanner-Shutdown

- **作者**: `chromeheartbeat`
- **地址**: https://github.com/chromeheartbeat/Network-Scanner-Shutdown
- **功能**: Python 网络扫描工具
- **特点**:
  - 检测连接设备
  - 识别 PC、服务器、移动设备、摄像头等
  - 可远程关闭 PC/服务器

---

## 4. NetDiscover-Pro

- **作者**: `ahirankush771`
- **地址**: https://github.com/ahirankush771/NetDiscover-Pro
- **功能**: 高级本地网络扫描器
- **特点**:
  - 端口扫描
  - 摄像头检测
  - 操作系统猜测

---

## 5. AGONY

- **作者**: `The-Red-Serpent`
- **地址**: https://github.com/The-Red-Serpent/AGONY
- **功能**: 隐秘网络扫描器
- **特点**:
  - 使用 ARP 发现所有设备
  - 检测笔记本、IoT 设备、打印机、路由器、摄像头
  - 发送 ARP 请求到指定范围内的所有 IP 地址

---

## 对比总结

### 我们的项目 `wifi-camera-detector` 的优势：

✅ **中文界面** - 更适合国内用户
✅ **多线程扫描** - 速度较快
✅ **集成 GUI** - 操作简单
✅ **风险评分机制** - 专门的可疑度评估

### 可以借鉴的功能：

📌 **ONVIF 多播发现**（RogueVision）
📌 **RTSP 流指纹验证**
📌 **证据导出功能**
📌 **设备基线对比**

---

*最后更新: 2026-03-29*
