set(TOL_SOURCE
        src-file.cpp
        lexer.cpp
        symtable.cpp
        compilation-errors.cpp
        compiler-state.cpp
        ast.cpp
        ast-from-tokens.cpp
        constant-evaluator.cpp
		gen-entrypoints.cpp
        pack-unpack-api.cpp
        pack-unpack-serializers.cpp
        send-message-api.cpp
        maps-kv-api.cpp
        pipe-discover-parse-sources.cpp
        pipe-register-symbols.cpp
        pipe-resolve-identifiers.cpp
        pipe-resolve-types.cpp
        pipe-calc-rvalue-lvalue.cpp
        pipe-infer-types-and-calls.cpp
        pipe-check-inferred-types.cpp
        pipe-refine-lvalue-for-mutate.cpp
        pipe-check-rvalue-lvalue.cpp
        pipe-check-private-fields.cpp
        pipe-check-pure-impure.cpp
        pipe-check-const-expr.cpp
        pipe-mini-borrow-checker.cpp
        pipe-optimize-boolean-expr.cpp
        pipe-detect-inline-in-place.cpp
        pipe-check-serialized-fields.cpp
        pipe-lower-contract.cpp
        pipe-check-query-id-propagation.cpp
        pipe-lazy-load-insertions.cpp
        pipe-transform-on-message.cpp
        pipe-ast-to-legacy.cpp
        pipe-find-unused-symbols.cpp
        pipe-generate-fif-output.cpp
        type-system.cpp
        type-transition.cpp
        smart-casts-cfg.cpp
        generics-helpers.cpp
        lazy-helpers.cpp
        overload-resolution.cpp
        abscode.cpp
        analyzer.cpp
        asmops.cpp
        builtins.cpp
        stack-transform.cpp
        optimize.cpp
        pretty-print.cpp
        codegen.cpp
        tol.cpp
)

add_executable(tol tol-main.cpp ${TOL_SOURCE})
target_include_directories(tol PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_link_libraries(tol PUBLIC git tos_crypto_core)
if (WINGETOPT_FOUND)
  target_link_libraries_system(tol wingetopt)
endif ()
if (${TOL_DEBUG}) # -DTOL_DEBUG=1 in CMake options => #define TOL_DEBUG (for development purposes)
  message(STATUS "TOL_DEBUG is ON")
  target_compile_definitions(tol PRIVATE TOL_DEBUG=1)
endif()

if (USE_EMSCRIPTEN)
  add_executable(tolfiftlib tol-wasm.cpp ${TOL_SOURCE})
  target_include_directories(tolfiftlib PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
  target_link_libraries(tolfiftlib PUBLIC fift-lib git)
  target_link_options(tolfiftlib PRIVATE
          -sEXPORTED_RUNTIME_METHODS=UTF8ToString,stringToUTF8,lengthBytesUTF8,addFunction,removeFunction,setValue
          -sEXPORTED_FUNCTIONS=_tol_compile,_tol_version,_malloc,_free,_setThrew
          -sEXPORT_NAME=CompilerModule
          -sFILESYSTEM=0
          -Oz
          -sIGNORE_MISSING_MAIN=1
          -sAUTO_NATIVE_LIBRARIES=0
          -sDYNAMIC_EXECUTION=0
          -sMODULARIZE=1
          -sTOTAL_STACK=131072
          -sTOTAL_MEMORY=33554432
          -sALLOW_MEMORY_GROWTH=1
          -sALLOW_TABLE_GROWTH=1
          -sENVIRONMENT=node,web
          -fexceptions
          -flto
  )
  target_compile_options(tolfiftlib PRIVATE -fexceptions -fno-stack-protector -flto)
endif ()

install(TARGETS tol RUNTIME DESTINATION bin)
