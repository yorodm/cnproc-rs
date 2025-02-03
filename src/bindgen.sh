#!/bin/bash
bindgen \
    --no-doc-comments \
    --use-core \
    --no-prepend-enum-name \
    --ctypes-prefix 'libc' \
    --formatter=prettyplease \
    --raw-line '#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals, unused)]use libc::*;' \
    wrapper.h -o binding.rs
