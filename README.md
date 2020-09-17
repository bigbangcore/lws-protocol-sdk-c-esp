# LWS-IoT SDK for ESP32/ESP8266

## 目录结构说明

* `components/lws-iot-esp` 实际的 LWS IoT SDK 库源码

## 安装配置 

### 安装 ESP32/ESP8266 开发环境

* [Windows 下安装配置 ESP8266/ESP32 开发环境](./docs/esp-env.md)

## 用法

将 `components/lws-iot-esp` 目录复制到客户项目的 `components` 目录中，修改客户项目的 `CMakeLists.txt` 文件，
添加引用，如：

```cmake
idf_component_register(
    SRCS "src/main.c"
    INCLUDE_DIRS "./include"
    REQUIRES lws-iot-esp  
)
```