# Toslib C++ basic usage examples

Toslib should be prebuilt and installed to local subdirectory `toslib/`:
```
cd <path to Ton sources>
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX:PATH=../example/cpp/toslib ..
cmake --build . --target install
```

Then you can build the examples:
```
cd <path to Ton sources>/example/cpp
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DToslib_DIR=<full path to Ton sources>/example/cpp/toslib/lib/cmake/Toslib ..
cmake --build .
```

To run `tonjson_example` you may need to manually copy a `toslibjson` shared library from `toslib/bin` to a directory containing built binaries.
