# Windows 下安装配置 ESP8266/ESP32 开发环境

## ESP8266/32 相同的前置操作

ESP8266/ESP32 均需要以下软件：

- Python3
- Ninja

Python 3 安装完毕以后，需要安装 Pip 工具。

Python3 和 Ninja 安装以后需要确保加入 %PATH% 环境变量。

## ESP8266 环境

下载解压 ESP8266_RTOS_SDK。

假设 ESP8266 的 SDK 解压路径为 `C:\esp8266_rtos_sdk`。

设置系统环境变量 `%IDF_PATH%` 指向  `C:\esp8266_rtos_sdk`。

### 安装 python 需求

执行：

```cmd
pip3 install --user -r %IDF_PATH%\requirements.txt
```

或者：
```cmd
python -m pip install --user -r %IDF_PATH%\requirements.txt
```

### 安装工具链

下载解压以下链接的 ESP8266 的编译器工具链，并将解压出来的 `\bin` 目录加入 `%PATH%` 环境变量。

[https://dl.espressif.com/dl/xtensa-lx106-elf-win32-1.22.0-100-ge567ec7-5.2.0.zip](url)


## ESP32 环境

操作基本与 ESP8266 相同，不同的是更换为 `ESP-IDF` SDK 和 ESP32 专用的编译器工具链。


## 使用

环境安装完毕以后，ESP8266 和 ESP32 的 `idf.py` 工具使用均是相同的：

在项目目录中使用 `python %IDF_PATH\tools\idf.py build` 来构建或烧录项目。

执行：

```cmd
python %IDF_PATH\tools\idf.py --help
```

获取命令帮助。