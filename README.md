# 网络数字孪生系统

## 项目目标
构建一个实时显示网络拓扑和流量状态的数字孪生系统。

## 系统架构

### 1. 物理网络层
- **工具**: Mininet
- **功能**: 
  - 创建SDN网络环境
  - 模拟网络拓扑变化
  - 生成真实网络流量

### 2. 控制层
- **工具**: Ryu Controller
- **功能**:
  - 网络拓扑发现
  - 链路状态监控
  - 流量统计收集
  - REST API提供

### 3. 数字孪生层
- **工具**: Python (NetworkX, Matplotlib)
- **功能**:
  - 拓扑数据处理
  - 网络图构建
  - 数据可视化

### 4. 展示层
- **工具**: Flask, WebSocket
- **功能**:
  - Web界面展示
  - 实时数据更新
  - 交互式操作

## 项目结构
/network-digital-twin
├── physical_network/
│ ├── topo.py # Mininet拓扑定义
│ └── custom_topo.py # 自定义拓扑模板
├── controller/
│ ├── ryu_app.py # Ryu控制器应用
│ └── topology_rest.py # REST API实现
├── digital_twin/
│ ├── network_model.py # 数字网络模型
│ └── visualizer.py # 可视化模块
├── web_interface/
│ ├── app.py # Flask应用
│ ├── static/ # 静态资源
│ └── templates/ # HTML模板
└── utils/
├── config.py # 配置文件
└── monitor.py # 监控更新模块
