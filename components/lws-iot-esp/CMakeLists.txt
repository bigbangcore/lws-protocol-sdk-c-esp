FILE(GLOB_RECURSE LWS_IOT_SOURCES 
    "./lws-protocol-sdk-c/*.c" 
    "./lws-protocol-sdk-c/*.cpp" 
)

SET(LWS_IOT_INCLUDE_DIRS "./lws-protocol-sdk-c")


idf_component_register(
    SRCS ${LWS_IOT_SOURCES}
    INCLUDE_DIRS ${LWS_IOT_INCLUDE_DIRS}
    REQUIRES esp_event
)

