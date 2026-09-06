add_library(extwatch_warnings INTERFACE)
if(MSVC)
    target_compile_options(extwatch_warnings INTERFACE /W4 /permissive- /utf-8 /wd4267)
else()
    target_compile_options(extwatch_warnings INTERFACE -Wall -Wextra -Wpedantic -Wshadow)
endif()

configure_file(core/version.h.in "${CMAKE_CURRENT_BINARY_DIR}/generated/extwatch/version.h" @ONLY)

add_library(extwatch_core STATIC
    core/browserkind.cpp core/browserkind.h
    core/discovery.cpp core/discovery.h
    core/chrometime.cpp core/chrometime.h
    core/crxid.cpp core/crxid.h
    core/prefs.cpp core/prefs.h
    core/manifest.cpp core/manifest.h
    core/hashing.cpp core/hashing.h
    core/blobstore.cpp core/blobstore.h
    core/database.cpp core/database.h
    core/inventory.cpp core/inventory.h
    core/scanner.cpp core/scanner.h
    core/jstree.cpp core/jstree.h
    core/jsanalysis.cpp core/jsanalysis.h
    core/prettify.cpp core/prettify.h
    core/textdiff.cpp core/textdiff.h
    core/signature.cpp core/signature.h
    core/rules.cpp core/rules.h
    core/analyzer.cpp core/analyzer.h
    core/package.cpp core/package.h
    core/watcher.cpp core/watcher.h
    core/autostart.cpp core/autostart.h
    core/actions.cpp core/actions.h
    core/storemeta.cpp core/storemeta.h
    core/storetracker.cpp core/storetracker.h
    core/nativemessaging.cpp core/nativemessaging.h
    core/companion.cpp core/companion.h
    core/jsonutil.h
)
target_include_directories(extwatch_core
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(extwatch_core
    PUBLIC Qt6::Core Qt6::Sql Qt6::Concurrent Qt6::Network Qt6::Gui tree_sitter tree_sitter_javascript dtl miniz
    PRIVATE extwatch_warnings)

qt_add_executable(extwatch
    main.cpp
    cli/cli.cpp cli/cli.h
    app/trayapp.cpp app/trayapp.h
    app/mainwindow.cpp app/mainwindow.h
    app/extensiondetail.cpp app/extensiondetail.h
    app/diffview.cpp app/diffview.h
    app/jshighlighter.cpp app/jshighlighter.h
    app/settingsdialog.cpp app/settingsdialog.h
    app/appsettings.cpp app/appsettings.h
    app/companionserver.cpp app/companionserver.h
    app/companiondialog.cpp app/companiondialog.h
    nativehost/nativehost.cpp nativehost/nativehost.h
)
qt_add_resources(extwatch "extwatch_icons"
    PREFIX "/"
    FILES app/icons/tray.svg app/icons/tray-alert.svg app/icons/app.svg)
qt_add_resources(extwatch "extwatch_companion"
    PREFIX "/companion"
    BASE "${CMAKE_SOURCE_DIR}/companion"
    FILES "${CMAKE_SOURCE_DIR}/companion/manifest.json" "${CMAKE_SOURCE_DIR}/companion/sw.js"
          "${CMAKE_SOURCE_DIR}/companion/icons/icon16.png" "${CMAKE_SOURCE_DIR}/companion/icons/icon48.png"
          "${CMAKE_SOURCE_DIR}/companion/icons/icon128.png")
# Qt6::Svg is linked explicitly so deployment tools ship the framework the SVG icon engine needs.
target_link_libraries(extwatch PRIVATE extwatch_core Qt6::Gui Qt6::Widgets Qt6::Svg Qt6::Concurrent extwatch_warnings)

if(APPLE AND EXTWATCH_MACOS_BUNDLE)
    set(EXTWATCH_MIN_MACOS "${CMAKE_OSX_DEPLOYMENT_TARGET}")
    if(NOT EXTWATCH_MIN_MACOS)
        set(EXTWATCH_MIN_MACOS "12.0")
    endif()
    set(EXTWATCH_ICNS "${CMAKE_SOURCE_DIR}/packaging/macos/ExtWatch.icns")
    target_sources(extwatch PRIVATE "${EXTWATCH_ICNS}")
    set_source_files_properties("${EXTWATCH_ICNS}" PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
    set_target_properties(extwatch PROPERTIES
        MACOSX_BUNDLE ON
        OUTPUT_NAME ExtWatch
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_SOURCE_DIR}/packaging/macos/Info.plist.in"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
        MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
        MACOSX_BUNDLE_ICON_FILE "ExtWatch.icns")
endif()
if(WIN32)
    # Embed the icon and version info into extwatch.exe.
    configure_file("${CMAKE_SOURCE_DIR}/packaging/windows/extwatch.rc.in" "${CMAKE_CURRENT_BINARY_DIR}/extwatch.rc" @ONLY)
    target_sources(extwatch PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/extwatch.rc")
endif()

include(GNUInstallDirs)
if(APPLE AND EXTWATCH_MACOS_BUNDLE)
    install(TARGETS extwatch BUNDLE DESTINATION .)
else()
    install(TARGETS extwatch RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    if(UNIX AND NOT APPLE)
        install(FILES "${CMAKE_SOURCE_DIR}/packaging/linux/extwatch.desktop" DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
        install(FILES "${CMAKE_SOURCE_DIR}/packaging/linux/extwatch.png" DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/256x256/apps)
    endif()
endif()
