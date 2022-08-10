#create logical links in order to keep legacy names of apps
macro(CREATE_SYMLINK _source _dest)
    set(source ${CMAKE_CURRENT_SOURCE_DIR}/${_source})
    set(dest ${CMAKE_CURRENT_BINARY_DIR}/${_dest})
    list(APPEND symlinks ${dest})
    add_custom_command(
        DEPENDS ${source} OUTPUT ${dest}
        COMMAND ln -sf ${_source} ${_dest}
    )
endmacro(CREATE_SYMLINK)
