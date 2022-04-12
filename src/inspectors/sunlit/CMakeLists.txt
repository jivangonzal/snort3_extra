cmake_minimum_required ( VERSION 3.4.3 )
project ( sunlit CXX )

set (CMAKE_PREFIX_PATH /home/jigonzal/snort-source-files/snort3_extra-3.1.25.0/libtorch)

find_package(Torch REQUIRED)

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    sunlit MODULE
    sunlit.cc
)

if ( APPLE )
    set_target_properties (
       sunlit 
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
   sunlit 
    PROPERTIES
        PREFIX ""
)

foreach (TORCH_LIBRARY IN LISTS TORCH_LIBRARIES)
    link_libraries(${TORCH_LIBRARY})
endforeach (TORCH_LIBRARY)

target_include_directories (
    sunlit PUBLIC
    ${SNORT3_INCLUDE_DIRS}
    ${TORCH_INCLUDE_DIRS}
)

install (
    TARGETS sunlit
    LIBRARY
        DESTINATION "${INSPECTOR_INSTALL_PATH}"
)
