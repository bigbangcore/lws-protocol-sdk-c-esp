FILE(GLOB_RECURSE LWS_IOT_SOURCES 
    "./src/*.c" 
    "./src/*.cpp" 
)

SET(LWS_IOT_INCLUDE_DIRS "./include")


idf_component_register(
    SRCS ${LWS_IOT_SOURCES}
    INCLUDE_DIRS ${LWS_IOT_INCLUDE_DIRS}
    REQUIRES esp_event
)

