file(GLOB_RECURSE LWS_IOT_APP_SOURCES 
    "./src/*.c" 
    "./src/*.cpp" 
)

set(LWS_IOT_APP_INCLUDE_DIRS "./include")

idf_component_register(
    SRCS ${LWS_IOT_APP_SOURCES}
    INCLUDE_DIRS ${LWS_IOT_APP_INCLUDE_DIRS}
    REQUIRES lws-iot-esp spi_flash json nvs_flash wpa_supplicant tcpip_adapter esp_event smartconfig_ack
)