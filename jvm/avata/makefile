MAKEFLAGS = -s

name = avata
version := $(shell grep version gradle.properties | cut -d'=' -f2)

ifeq ($(JAVA_HOME),)
JAVA_HOME := $(shell dirname $$(dirname $$(readlink -f $$(command -v javac))))
endif

get-java-version = $(shell "$1" -version 2>&1 \
		| sed -n -e 's/.*version "1\.\([0-9][0-9]*\).*/\1/p' \
					-e 's/.*version "\([0-9][0-9]*\).*/\1/p' \
		| head -n 1)

host-java-version := $(call get-java-version,$(JAVA_HOME)/bin/java)
ifeq ($(filter 6 7 8,$(host-java-version)),)
java-version := 8
else
java-version := $(host-java-version)
endif

build-arch := $(shell uname -m \
	| sed -e 's/^i.86$$/i386/' \
	      -e 's/^x86pc$$/i386/' \
	      -e 's/amd64/x86_64/' \
	      -e 's/^aarch64$$/arm64/' \
	      -e '/^arm64/!s/^arm.*$$/arm/')

build-platform := \
	$(shell uname -s | tr [:upper:] [:lower:] \
		| sed \
			-e 's/^mingw64.*$$/mingw32/' \
			-e 's/^mingw32.*$$/mingw32/' \
			-e 's/^cygwin.*$$/cygwin/' \
			-e 's/^darwin.*$$/macosx/')

arch = $(build-arch)
target-arch = $(arch)

host-platform = \
	$(subst cygwin,windows,$(subst mingw32,windows,$(build-platform)))

platform = $(host-platform)

mode = fast
process = interpret

ifneq ($(process),interpret)
	options := -$(process)
endif
ifneq ($(mode),fast)
	options := $(options)-$(mode)
endif
ifeq ($(filter debug debug-fast fast stress stress-major small,$(mode)),)
	x := $(error "'$(mode)' is not a valid mode (choose one of: debug debug-fast fast stress stress-major small)")
endif

ifneq ($(process),interpret)
	x := $(error "'$(process)' is not a supported TOS consensus build mode; use process=interpret")
endif

ifneq ($(openjdk)$(openjdk-src),)
	x := $(error "OpenJDK runtime/classpath builds were removed from the TOS Avata profile; use the Avata/TOS rt tree")
endif

ifneq ($(android),)
	x := $(error "Android/libcore builds were removed from the TOS Avata profile")
endif

ifneq ($(bootimage)$(bootimage-test),)
	x := $(error "bootimage/codeimage builds were removed from the TOS Avata profile")
endif

ifneq ($(tails)$(continuations)$(lzma),)
	x := $(error "legacy tails/continuations/lzma build variants are not part of the TOS Avata profile")
endif

ifeq ($(filter x86_64 i386 arm arm64,$(arch)),)
	x := $(error "'$(arch)' is not a supported architecture (choose one of: x86_64 i386 arm arm64)")
endif

ifeq ($(platform),darwin)
	x := $(error "please use 'platform=macosx' or 'platform=ios' instead of 'platform=$(platform)'")
endif

ifneq ($(ios),)
	x := $(error "please use 'platform=ios' instead of 'ios=true'")
endif

ifeq ($(filter linux windows macosx ios freebsd,$(platform)),)
	x := $(error "'$(platform)' is not a supported platform (choose one of: linux windows macosx ios freebsd)")
endif

ifeq ($(platform),macosx)
	ifeq ($(arch),arm)
		x := $(error "32-bit arm is not supported on macosx; use 'platform=ios' for ios-arm or 'arch=arm64' for Apple Silicon")
	endif
endif

ifeq ($(platform),ios)
	ifeq ($(filter i386 x86_64 arm arm64,$(arch)),)
		x := $(error "please specify 'arch=i386', 'arch=x86_64', 'arch=arm', or 'arch=arm64' with 'platform=ios'")
	endif
endif

root := $(shell (cd .. && pwd))
build = build/$(platform)-$(arch)$(options)
classpath-build = $(build)/rt
test-build = $(build)/test
src = src
classpath-src = rt
test = test
unittest = unittest
win32 ?= $(root)/win32
win64 ?= $(root)/win64

classpath = avata

ifeq ($(use-werror),true)
	werror = -Werror
endif

test-executable = $(shell pwd)/$(executable)
boot-classpath = $(classpath-build)

native-path = echo

platform-kernel = $(subst macosx,darwin,$(subst ios,darwin,$1))

build-kernel = $(call platform-kernel,$(build-platform))
kernel = $(call platform-kernel,$(platform))

ifeq ($(build-platform),cygwin)
	native-path = cygpath -m
endif

windows-path = echo

path-separator = :

ifneq (,$(filter mingw32 cygwin,$(build-platform)))
	path-separator = ;
endif

target-path-separator = :

ifeq ($(platform),windows)
	target-path-separator = ;
endif

library-path-variable = LD_LIBRARY_PATH

ifeq ($(build-kernel),darwin)
	library-path-variable = DYLD_LIBRARY_PATH
endif

library-path = $(library-path-variable)=$(build)

ifeq ($(classpath),avata)
	jni-sources := $(shell find $(classpath-src) -name '*.cpp')
	jni-objects = $(call cpp-objects,$(jni-sources),$(classpath-src),$(build))
	classpath-objects = $(jni-objects)
endif

input = List

ifeq ($(use-clang),true)
	build-cxx = clang++ -std=c++11
	build-cc = clang
else
	build-cxx = g++
	build-cc = gcc
endif

mflag =
ifneq ($(kernel),darwin)
	ifeq ($(arch),i386)
		mflag = -m32
	endif
	ifeq ($(arch),x86_64)
		mflag = -m64
	endif
endif

target-format = elf

cxx = $(build-cxx) $(mflag)
cc = $(build-cc) $(mflag)

ar = ar
ranlib = ranlib
dlltool = dlltool
vg = nice valgrind --num-callers=32 --db-attach=yes --freelist-vol=100000000
vg += --leak-check=full --suppressions=valgrind.supp
db = gdb --args
javac = "$(JAVA_HOME)/bin/javac" -encoding UTF-8
javah = "$(JAVA_HOME)/bin/javah"
jar = "$(JAVA_HOME)/bin/jar"
strip = strip
strip-all = --strip-all

rdynamic = -rdynamic

cflags_debug = -O0 -g3
cflags_debug_fast = -O0 -g3
cflags_stress = -O0 -g3
cflags_stress_major = -O0 -g3
ifeq ($(use-clang),true)
	cflags_fast = -O3 -g3
	cflags_small = -Oz -g3
else
	cflags_fast = -O3 -g3
	cflags_small = -Os -g3
endif

# note that we suppress the non-virtual-dtor warning because we never
# use the delete operator, which means we don't need virtual
# destructors:
warnings = -Wall -Wextra $(werror) -Wunused-parameter -Winit-self \
	-Wno-non-virtual-dtor

target-cflags = -DTARGET_BYTES_PER_WORD=$(pointer-size)
softfloat-include-cflags = \
	-I$(src)/softfloat/berkeley \
	-I$(src)/softfloat/berkeley/source/8086-SSE \
	-I$(src)/softfloat/berkeley/source/include

common-cflags = $(warnings) -std=c++0x -fno-rtti -fno-exceptions -I$(classpath-src) \
	"-I$(JAVA_HOME)/include" -I$(src) -I$(build) -Iinclude \
	$(softfloat-include-cflags) $(classpath-cflags) \
	-D__STDC_LIMIT_MACROS -D_JNI_IMPLEMENTATION_ -DAVATA_VERSION=\"$(version)\" \
	-DAVATA_INFO="\"$(info)\"" \
	-DUSE_ATOMIC_OPERATIONS -DAVATA_JAVA_HOME=\"$(javahome)\" $(target-cflags)

asmflags = $(target-cflags) -I$(src)

ifneq (,$(filter i386 x86_64,$(arch)))
	ifeq ($(use-frame-pointer),true)
		common-cflags += -fno-omit-frame-pointer -DAVATA_USE_FRAME_POINTER
		asmflags += -DAVATA_USE_FRAME_POINTER
	endif
endif

build-cflags = $(common-cflags) -fPIC -fvisibility=hidden \
	"-I$(JAVA_HOME)/include/linux" -I$(src) -pthread

converter-cflags = -D__STDC_CONSTANT_MACROS -std=c++0x -Iinclude/ -Isrc/ \
	-fno-rtti -fno-exceptions \
	-DAVATA_TARGET_ARCH=AVATA_ARCH_UNKNOWN \
	-DAVATA_TARGET_FORMAT=AVATA_FORMAT_UNKNOWN \
	-Wall -Wextra $(werror) -Wunused-parameter -Winit-self -Wno-non-virtual-dtor

cflags = $(build-cflags)

common-lflags = -lm -lz

ifeq ($(use-clang),true)
	ifeq ($(build-kernel),darwin)
		common-lflags += -Wl,-export_dynamic
	else
		ifneq ($(platform),windows)
			common-lflags += -Wl,-E
		else
			common-lflags += -Wl,--export-all-symbols
		endif
	endif
endif

build-lflags = -lz -lpthread -ldl

lflags = $(common-lflags) -lpthread -ldl

build-system = posix

system = posix
asm = x86

pointer-size = 8

so-prefix = lib
so-suffix = .so

static-prefix = lib
static-suffix = .a

output = -o $(1)
asm-output = -o $(1)
asm-input = -c $(1)
asm-format = S
as = $(cc)
ld = $(cc)
build-ld = $(build-cc)
build-ld-cpp = $(build-cxx)

default-remote-test-host = localhost
default-remote-test-port = 22
ifeq ($(remote-test-host),)
	remote-test-host = $(default-remote-test-host)
else
	remote-test = true
endif
ifeq ($(remote-test-port),)
	remote-test-port = $(default-remote-test-port)
else
	remote-test = true
endif
remote-test-user = ${USER}
remote-test-dir = /tmp/avata-test-${USER}

static = -static
shared = -shared

rpath = -Wl,-rpath=\$$ORIGIN -Wl,-z,origin

developer-dir := $(shell if test -d /Developer/Platforms/$(target).platform/Developer/SDKs; then echo /Developer; \
	else echo /Applications/Xcode.app/Contents/Developer; fi)

ifneq (,$(filter i386 arm,$(arch)))
	pointer-size = 4
endif

ifneq (,$(filter arm arm64,$(arch)))
	asm = arm

	ifneq ($(platform),ios)
		ifneq ($(arch),arm64)
			no-psabi = -Wno-psabi
			cflags += -marm $(no-psabi)

			# By default, assume we can't use armv7-specific instructions on
			# non-iOS platforms.  Ideally, we'd detect this at runtime.
			armv6=true
		endif
	endif

	ifneq ($(arch),$(build-arch))
		ifneq ($(kernel),darwin)
			ifeq ($(arch),arm64)
				cxx = aarch64-linux-gnu-g++
				cc = aarch64-linux-gnu-gcc
				ar = aarch64-linux-gnu-ar
				ranlib = aarch64-linux-gnu-ranlib
				strip = aarch64-linux-gnu-strip
			else
				cxx = arm-linux-gnueabi-g++
				cc = arm-linux-gnueabi-gcc
				ar = arm-linux-gnueabi-ar
				ranlib = arm-linux-gnueabi-ranlib
				strip = arm-linux-gnueabi-strip
			endif
		endif
	endif
endif

ifeq ($(armv6),true)
	cflags += -DAVATA_ASSUME_ARMV6
endif

ifeq ($(platform),ios)
	cflags += -DAVATA_IOS
	use-lto = false
endif

ifeq ($(build-kernel),darwin)
	build-cflags = $(common-cflags) -fPIC -fvisibility=hidden -I$(src)
	cflags += -Wno-deprecated-declarations
	build-lflags += -framework CoreFoundation
endif

ifeq ($(platform),qnx)
	cflags = $(common-cflags) -fPIC -fvisibility=hidden -I$(src)
	lflags = $(common-lflags) -lsocket
	ifeq ($(build-platform),qnx)
		build-cflags = $(common-cflags) -fPIC -fvisibility=hidden -I$(src)
		build-lflags = $(common-lflags)
	else
		ifeq ($(arch),i386)
			prefix = i486-pc-nto-qnx6.5.0-
		else
			prefix = arm-unknown-nto-qnx6.5.0-
		endif
	endif
	cxx = $(prefix)g++
	cc = $(prefix)gcc
	ar = $(prefix)ar
	ranlib = $(prefix)ranlib
	strip = $(prefix)strip
	rdynamic = -Wl,--export-dynamic
endif

ifeq ($(platform),freebsd)
# There is no -ldl on FreeBSD
	build-lflags = $(common-lflags) -lz -lpthread
	lflags = $(common-lflags) -lpthread
# include/freebsd instead of include/linux
	build-cflags = $(common-cflags) -fPIC -fvisibility=hidden \
		"-I$(JAVA_HOME)/include/freebsd" -I$(src) -pthread
	cflags = $(build-cflags)
endif
ifeq ($(kernel),darwin)
	target-format = macho
	ifeq (${OSX_SDK_SYSROOT},)
		OSX_SDK_SYSROOT = 10.6u
	endif
	ifeq (${OSX_SDK_VERSION},)
		OSX_SDK_VERSION = 10.6
	endif
	ifneq ($(build-kernel),darwin)
		cxx = i686-apple-darwin8-g++ $(mflag)
		cc = i686-apple-darwin8-gcc $(mflag)
		ar = i686-apple-darwin8-ar
		ranlib = i686-apple-darwin8-ranlib
		strip = i686-apple-darwin8-strip
		sysroot = /opt/mac/SDKs/MacOSX${OSX_SDK_SYSROOT}.sdk
		cflags = -I$(sysroot)/System/Library/Frameworks/JavaVM.framework/Versions/1.5.0/Headers/ \
			$(common-cflags) -fPIC -fvisibility=hidden -I$(src)
	endif

	ifneq ($(platform),ios)
		platform-dir = $(developer-dir)/Platforms/MacOSX.platform
		sdk-dir = $(platform-dir)/Developer/SDKs

		mac-version := $(shell \
				if test -d $(sdk-dir)/MacOSX10.11.sdk; then echo 10.11; \
			elif test -d $(sdk-dir)/MacOSX10.10.sdk; then echo 10.10; \
			elif test -d $(sdk-dir)/MacOSX10.9.sdk; then echo 10.9; \
			elif test -d $(sdk-dir)/MacOSX10.8.sdk; then echo 10.8; \
			elif test -d $(sdk-dir)/MacOSX10.7.sdk; then echo 10.7; \
			elif test -d $(sdk-dir)/MacOSX10.6.sdk; then echo 10.6; \
			else echo; fi)

		sysroot = $(sdk-dir)/MacOSX$(mac-version).sdk
	endif

	soname-flag =
	version-script-flag =
	lflags = $(common-lflags) -ldl -framework CoreFoundation -framework Foundation

	ifeq (,$(shell ld -v 2>&1 | grep cctools))
		lflags += -Wl,-compatibility_version,1.0.0
	endif

	ifneq ($(platform),ios)
		lflags +=	-framework CoreServices -framework SystemConfiguration \
			-framework Security
	endif
	rdynamic =
	strip-all = -S -x
	so-suffix = .dylib
	shared = -dynamiclib
	rpath =

	ifeq ($(platform),ios)
		ifeq ($(sim),true)
			target = iPhoneSimulator
			ifeq ($(arch),i386)
				arch-flag = -arch i386
			else
				arch-flag = -arch x86_64
				arch = x86_64
			endif
			release = Release-iphonesimulator
		else
			target = iPhoneOS
			ifeq ($(arch),arm)
				arch-flag = -arch armv7
			else
				arch-flag = -arch arm64
				arch = arm64
			endif
			release = Release-iphoneos
		endif

		platform-dir = $(developer-dir)/Platforms/$(target).platform
		sdk-dir = $(platform-dir)/Developer/SDKs

		ifeq ($(ios-version),)
			ios-version := 8.0
		endif

		sysroot = $(sdk-dir)/$(target).sdk

# apparently, the header files we need are part of the simulator SDK
# but not the device SDK, so we copy them from the former even if
# we're targeting the latter

		header-sysroot := $(subst iPhoneOS,iPhoneSimulator,$(sysroot))

		ios-bin = $(platform-dir)/Developer/usr/bin

		found-gcc = $(shell if test -f $(ios-bin)/gcc; then echo true; else echo false; fi)

		ifeq ($(found-gcc),false)
			use-clang = true
		endif

		ifeq ($(use-clang),true)
			cxx = clang -std=c++11
			cc = clang
		else
			cxx = $(ios-bin)/g++
			cc = $(ios-bin)/gcc
		endif

		flags = -isysroot $(sdk-dir)/$(target).sdk \
			$(arch-flag)

		classpath-extra-cflags += $(flags)
		cflags += $(flags)
		asmflags += $(flags)
		lflags += $(flags)

		ios-version-min=$(ios-version)
		ifdef ios_deployment_target
			ios-version-min=ios_deployment_target
		endif

		ifeq ($(sim),true)
			ifeq ($(arch),x86_64)
				classpath-extra-cflags += \
					-arch x86_64 -miphoneos-version-min=$(ios-version-min)
				cflags += -arch x86_64 -miphoneos-version-min=$(ios-version-min)
				asmflags += -arch x86_64 -miphoneos-version-min=$(ios-version-min)
				lflags += -arch x86_64 -miphoneos-version-min=$(ios-version-min)
			else
				classpath-extra-cflags += \
					-arch i386 -miphoneos-version-min=$(ios-version-min)
				cflags += -arch i386 -miphoneos-version-min=$(ios-version-min)
				asmflags += -arch i386 -miphoneos-version-min=$(ios-version-min)
				lflags += -arch i386 -miphoneos-version-min=$(ios-version-min)
			endif
		else
			ifeq ($(arch),arm64)
				classpath-extra-cflags += \
					-arch arm64 -miphoneos-version-min=$(ios-version-min)
				cflags += -arch arm64 -miphoneos-version-min=$(ios-version-min)
				asmflags += -arch arm64 -miphoneos-version-min=$(ios-version-min)
				lflags += -arch arm64 -miphoneos-version-min=$(ios-version-min)
			else
				classpath-extra-cflags += \
					-arch armv7 -miphoneos-version-min=$(ios-version-min)
				cflags += -arch armv7 -miphoneos-version-min=$(ios-version-min)
				asmflags += -arch armv7 -miphoneos-version-min=$(ios-version-min)
				lflags += -arch armv7 -miphoneos-version-min=$(ios-version-min)
			endif
		endif
	else # not ios
		ifeq ($(arch),i386)
				classpath-extra-cflags += \
					-arch i386 -mmacosx-version-min=${OSX_SDK_VERSION}
				cflags += -arch i386 -mmacosx-version-min=${OSX_SDK_VERSION}
				asmflags += -arch i386 -mmacosx-version-min=${OSX_SDK_VERSION}
				lflags += -arch i386 -mmacosx-version-min=${OSX_SDK_VERSION}
		endif

		ifeq ($(arch),x86_64)
				classpath-extra-cflags += -arch x86_64
				cflags += -arch x86_64
				asmflags += -arch x86_64
				lflags += -arch x86_64
		endif

		ifeq ($(arch),arm64)
				classpath-extra-cflags += -arch arm64 -mmacosx-version-min=11.0
				cflags += -arch arm64 -mmacosx-version-min=11.0
				asmflags += -arch arm64 -mmacosx-version-min=11.0
				lflags += -arch arm64 -mmacosx-version-min=11.0
		endif
	endif
	cflags += -I$(JAVA_HOME)/include/darwin
endif

find-tool = $(shell if ( command -v "$(1)$(2)" >/dev/null ); then (echo "$(1)$(2)") else (echo "$(2)"); fi)

ifeq ($(platform),windows)
	target-format = pe

	inc = "$(win32)/include"
	lib = "$(win32)/lib"

	system = windows

	so-prefix =
	so-suffix = .dll
	exe-suffix = .exe
	rpath =

	lflags = -L$(lib) $(common-lflags) -lws2_32 -lversion -luuid -liphlpapi \
		-lmswsock -mconsole

	cflags = -I$(inc) $(common-cflags) -DWINVER=0x0500 -U__STRICT_ANSI__

	ifeq (,$(filter mingw32 cygwin,$(build-platform)))
		prefix := $(shell i686-w64-mingw32-gcc --version >/dev/null 2>&1 \
			&& echo i686-w64-mingw32- || echo x86_64-w64-mingw32-)
		cxx = $(prefix)g++ -m32
		cc = $(prefix)gcc -m32
		dlltool = $(prefix)dlltool -mi386 --as-flags=--32
		ar = $(prefix)ar
		ranlib = $(prefix)ranlib
		strip = $(prefix)strip --strip-all
	else
		build-system = windows
		static-on-windows = -static
		common-cflags += "-I$(JAVA_HOME)/include/win32"
		build-cflags = $(common-cflags) -I$(src) -I$(inc) -mthreads \
			-D_WIN32_WINNT=0x0500
		build-lflags = -L$(lib) $(common-lflags)
		ifeq ($(build-platform),cygwin)
			build-cxx = i686-w64-mingw32-g++
			build-cc = i686-w64-mingw32-gcc
			dlltool = i686-w64-mingw32-dlltool
			ar = i686-w64-mingw32-ar
			ranlib = i686-w64-mingw32-ranlib
			strip = i686-w64-mingw32-strip
		endif
	endif

	ifeq ($(arch),x86_64)
		ifeq ($(build-platform),cygwin)
			build-cxx = x86_64-w64-mingw32-g++
			build-cc = x86_64-w64-mingw32-gcc
		endif
		cxx = x86_64-w64-mingw32-g++ $(mflag)
		cc = x86_64-w64-mingw32-gcc $(mflag)
		dlltool = $(call find-tool,x86_64-w64-mingw32-,dlltool)
		ar = $(call find-tool,x86_64-w64-mingw32-,ar)
		ranlib = $(call find-tool,x86_64-w64-mingw32-,ranlib)
		strip = $(call find-tool,x86_64-w64-mingw32-,strip)
		inc = "$(win64)/include"
		lib = "$(win64)/lib"
	else
		shared += -Wl,--add-stdcall-alias
	endif
endif

ifdef msvc
	target-format = pe
	windows-path = $(native-path)
	windows-java-home := $(shell $(windows-path) "$(JAVA_HOME)")
	zlib := $(shell $(windows-path) "$(win32)/msvc")
	ms_cl_compiler = regular
	as = $(build-cc)
	cxx = "$(msvc)/BIN/cl.exe"
	cc = $(cxx)
	ld = "$(msvc)/BIN/link.exe"
	mt = "mt.exe"
	ar = "$(msvc)/BIN/lib.exe"
	manifest-flags = -MANIFEST -MANIFESTFILE:$(@).manifest
	cflags = -nologo -DAVATA_VERSION=\"$(version)\" -D_JNI_IMPLEMENTATION_ \
		-DUSE_ATOMIC_OPERATIONS -DAVATA_JAVA_HOME=\"$(javahome)\" \
		-Fd$(build)/$(name).pdb -I"$(zlib)/include" -I$(src) -I$(classpath-src) \
		-I"$(build)" -Iinclude \
		-I"$(windows-java-home)/include" -I"$(windows-java-home)/include/win32" \
		-DTARGET_BYTES_PER_WORD=$(pointer-size)

	shared = -dll
	lflags = -nologo -LIBPATH:"$(zlib)/lib" -DEFAULTLIB:ws2_32 \
		-DEFAULTLIB:zlib -DEFAULTLIB:user32 -MANIFEST -debug
	output = -Fo$(1)

	cflags_debug = -Od -Zi -MDd
	cflags_debug_fast = -Od -Zi -DNDEBUG
	cflags_fast = -O2 -GL -Zi -DNDEBUG
	cflags_small = -O1s -Zi -GL -DNDEBUG
	ifeq ($(mode),fast)
		lflags += -LTCG
	endif
	ifeq ($(mode),small)
		lflags += -LTCG
	endif

	use-lto = false
	strip = :
endif

ifeq ($(mode),debug)
	optimization-cflags = $(cflags_debug)
	converter-cflags += $(cflags_debug)
	strip = :
endif
ifeq ($(mode),debug-fast)
	optimization-cflags = $(cflags_debug_fast) -DNDEBUG
	strip = :
endif
ifeq ($(mode),stress)
	optimization-cflags = $(cflags_stress) -DVM_STRESS
	strip = :
endif
ifeq ($(mode),stress-major)
	optimization-cflags = $(cflags_stress_major) -DVM_STRESS -DVM_STRESS_MAJOR
	strip = :
endif
ifeq ($(mode),fast)
	optimization-cflags = $(cflags_fast) -DNDEBUG
endif
ifeq ($(mode),small)
	optimization-cflags = $(cflags_small) -DNDEBUG
endif

ifeq ($(use-lto),true)
	ifeq ($(use-clang),true)
		optimization-cflags += -flto
		lflags += $(optimization-cflags)
	else
# only try to use LTO when GCC 4.6.0 or greater is available
		gcc-major := $(shell $(cc) -dumpversion | cut -f1 -d.)
		gcc-minor := $(shell $(cc) -dumpversion | cut -f2 -d.)
		ifeq ($(shell expr 4 \< $(gcc-major) \
				\| \( 4 \<= $(gcc-major) \& 6 \<= $(gcc-minor) \)),1)
			optimization-cflags += -flto
			no-lto = -fno-lto
			lflags += $(optimization-cflags)
		endif
	endif
endif

cflags += $(optimization-cflags)
softfloat-cflags = $(optimization-cflags) -Wall -Wextra $(werror) \
	-Werror-implicit-function-declaration -std=c99 -fPIC -fvisibility=hidden \
	-DSOFTFLOAT_FAST_INT64 -DSOFTFLOAT_ROUND_ODD -DINLINE_LEVEL=5 \
	-DSOFTFLOAT_FAST_DIV32TO16 -DSOFTFLOAT_FAST_DIV64TO32 \
	$(softfloat-include-cflags)

ifndef ms_cl_compiler
ifneq ($(kernel),darwin)
ifeq ($(arch),i386)
# this is necessary to support __sync_bool_compare_and_swap:
	cflags += -march=i586
	lflags += -march=i586
endif
endif
endif

c-objects = $(foreach x,$(1),$(patsubst $(2)/%.c,$(3)/%.o,$(x)))
cpp-objects = $(foreach x,$(1),$(patsubst $(2)/%.cpp,$(3)/%.o,$(x)))
cc-objects = $(foreach x,$(1),$(patsubst $(2)/%.cc,$(3)/%.o,$(x)))
asm-objects = $(foreach x,$(1),$(patsubst $(2)/%.$(asm-format),$(3)/%-asm.o,$(x)))
java-classes = $(foreach x,$(1),$(patsubst $(2)/%.java,$(3)/%.class,$(x)))
noop-files = $(foreach x,$(1),$(patsubst $(2)/%,$(3)/%,$(x)))

generated-code = \
	$(build)/type-enums.cpp \
	$(build)/type-declarations.cpp \
	$(build)/type-constructors.cpp \
	$(build)/type-initializations.cpp \
	$(build)/type-java-initializations.cpp \
	$(build)/type-name-initializations.cpp \
	$(build)/type-maps.cpp

vm-depends := $(generated-code) \
	$(shell find src include -name '*.h' -or -name '*.inc.cpp')

vm-sources = \
	$(src)/system/$(system).cpp \
	$(wildcard $(src)/system/$(system)/*.cpp) \
	$(src)/finder.cpp \
	$(src)/machine.cpp \
	$(src)/util.cpp \
	$(src)/util/abort.cpp \
	$(src)/util/arg-parser.cpp \
	$(src)/heap/heap.cpp \
	$(src)/$(process).cpp \
	$(src)/classpath-$(classpath).cpp \
	$(src)/builtin.cpp \
	$(src)/jnienv.cpp \
	$(src)/process.cpp \
	$(src)/heapdump.cpp

softfloat-sources = \
	$(src)/softfloat/berkeley/source/softfloat_state.c \
	$(src)/softfloat/berkeley/source/s_countLeadingZeros8.c \
	$(src)/softfloat/berkeley/source/s_countLeadingZeros16.c \
	$(src)/softfloat/berkeley/source/s_countLeadingZeros32.c \
	$(src)/softfloat/berkeley/source/s_countLeadingZeros64.c \
	$(src)/softfloat/berkeley/source/s_shiftRightJam32.c \
	$(src)/softfloat/berkeley/source/s_shiftRightJam64.c \
	$(src)/softfloat/berkeley/source/s_shiftRightJam64Extra.c \
	$(src)/softfloat/berkeley/source/s_shortShiftRightJam64.c \
	$(src)/softfloat/berkeley/source/s_shortShiftRightJam64Extra.c \
	$(src)/softfloat/berkeley/source/s_mul64To128.c \
	$(src)/softfloat/berkeley/source/s_approxRecip_1Ks.c \
	$(src)/softfloat/berkeley/source/s_approxRecip32_1.c \
	$(src)/softfloat/berkeley/source/s_roundToI32.c \
	$(src)/softfloat/berkeley/source/s_roundToI64.c \
	$(src)/softfloat/berkeley/source/s_normSubnormalF32Sig.c \
	$(src)/softfloat/berkeley/source/s_roundPackToF32.c \
	$(src)/softfloat/berkeley/source/s_normRoundPackToF32.c \
	$(src)/softfloat/berkeley/source/s_addMagsF32.c \
	$(src)/softfloat/berkeley/source/s_subMagsF32.c \
	$(src)/softfloat/berkeley/source/f32_add.c \
	$(src)/softfloat/berkeley/source/f32_sub.c \
	$(src)/softfloat/berkeley/source/f32_mul.c \
	$(src)/softfloat/berkeley/source/f32_div.c \
	$(src)/softfloat/berkeley/source/f32_lt.c \
	$(src)/softfloat/berkeley/source/f32_to_i32.c \
	$(src)/softfloat/berkeley/source/f32_to_i64.c \
	$(src)/softfloat/berkeley/source/f32_to_f64.c \
	$(src)/softfloat/berkeley/source/i32_to_f32.c \
	$(src)/softfloat/berkeley/source/i64_to_f32.c \
	$(src)/softfloat/berkeley/source/s_normSubnormalF64Sig.c \
	$(src)/softfloat/berkeley/source/s_roundPackToF64.c \
	$(src)/softfloat/berkeley/source/s_normRoundPackToF64.c \
	$(src)/softfloat/berkeley/source/s_addMagsF64.c \
	$(src)/softfloat/berkeley/source/s_subMagsF64.c \
	$(src)/softfloat/berkeley/source/f64_add.c \
	$(src)/softfloat/berkeley/source/f64_sub.c \
	$(src)/softfloat/berkeley/source/f64_mul.c \
	$(src)/softfloat/berkeley/source/f64_div.c \
	$(src)/softfloat/berkeley/source/f64_lt.c \
	$(src)/softfloat/berkeley/source/f64_to_i32.c \
	$(src)/softfloat/berkeley/source/f64_to_i64.c \
	$(src)/softfloat/berkeley/source/f64_to_f32.c \
	$(src)/softfloat/berkeley/source/i32_to_f64.c \
	$(src)/softfloat/berkeley/source/i64_to_f64.c \
	$(src)/softfloat/berkeley/source/8086-SSE/softfloat_raiseFlags.c \
	$(src)/softfloat/berkeley/source/8086-SSE/s_f32UIToCommonNaN.c \
	$(src)/softfloat/berkeley/source/8086-SSE/s_commonNaNToF32UI.c \
	$(src)/softfloat/berkeley/source/8086-SSE/s_propagateNaNF32UI.c \
	$(src)/softfloat/berkeley/source/8086-SSE/s_f64UIToCommonNaN.c \
	$(src)/softfloat/berkeley/source/8086-SSE/s_commonNaNToF64UI.c \
	$(src)/softfloat/berkeley/source/8086-SSE/s_propagateNaNF64UI.c \
	$(src)/softfloat/tos_softfloat_fmod.c

vm-asm-sources = $(src)/$(arch).$(asm-format)

target-asm = $(asm)

vm-cpp-objects = $(call cpp-objects,$(vm-sources),$(src),$(build))
softfloat-objects = $(call c-objects,$(softfloat-sources),$(src),$(build))
vm-asm-objects = $(call asm-objects,$(vm-asm-sources),$(src),$(build))
vm-objects = $(vm-cpp-objects) $(softfloat-objects) $(vm-asm-objects)

heapwalk-sources = $(src)/heapwalk.cpp
heapwalk-objects = \
	$(call cpp-objects,$(heapwalk-sources),$(src),$(build))

unittest-objects = $(call cpp-objects,$(unittest-sources),$(unittest),$(build)/unittest)

vm-heapwalk-objects = $(heapwalk-objects)

vm-classpath-objects = $(classpath-object)
cflags += -DBOOT_CLASSPATH=\"[classpathJar]\" \
	-DAVATA_CLASSPATH=\"[classpathJar]\"

cflags += $(extra-cflags)
lflags += $(extra-lflags)

driver-source = $(src)/main.cpp
driver-object = $(build)/main.o
driver-dynamic-objects = \
	$(build)/main-dynamic.o

boot-source = $(src)/boot.cpp
boot-object = $(build)/boot.o

generator-depends := $(wildcard $(src)/*.h)
generator-sources = \
	$(src)/tools/type-generator/main.cpp \
	$(src)/system/$(build-system).cpp \
	$(wildcard $(src)/system/$(build-system)/*.cpp) \
	$(src)/finder.cpp \
	$(src)/util/abort.cpp \
	$(src)/util/arg-parser.cpp

generator-cpp-objects = \
	$(foreach x,$(1),$(patsubst $(2)/%.cpp,$(3)/%-build.o,$(x)))
generator-c-objects = \
	$(foreach x,$(1),$(patsubst $(2)/%.c,$(3)/%-build.o,$(x)))
generator-objects = \
	$(call generator-cpp-objects,$(generator-sources),$(src),$(build))
generator = $(build)/generator

all-depends = $(shell find include -name '*.h')

object-writer-depends = $(shell find $(src)/tools/object-writer -name '*.h')
object-writer-sources = $(shell find $(src)/tools/object-writer -name '*.cpp')
object-writer-objects = $(call cpp-objects,$(object-writer-sources),$(src),$(build))

binary-to-object-depends = $(shell find $(src)/tools/binary-to-object/ -name '*.h')
binary-to-object-sources = $(shell find $(src)/tools/binary-to-object/ -name '*.cpp')
binary-to-object-objects = $(call cpp-objects,$(binary-to-object-sources),$(src),$(build))

converter-sources = $(object-writer-sources)

converter-tool-depends = $(binary-to-object-depends) $(all-depends)
converter-tool-sources = $(binary-to-object-sources)

converter-objects = $(call cpp-objects,$(converter-sources),$(src),$(build))
converter-tool-objects = $(call cpp-objects,$(converter-tool-sources),$(src),$(build))
converter = $(build)/binaryToObject/binaryToObject

static-library = $(build)/$(static-prefix)$(name)$(static-suffix)
executable = $(build)/$(name)${exe-suffix}
dynamic-library = $(build)/$(so-prefix)jvm$(so-suffix)
executable-dynamic = $(build)/$(name)-dynamic$(exe-suffix)

unittest-executable = $(build)/$(name)-unittest${exe-suffix}

classpath-sources := $(shell find $(classpath-src) -name '*.java')

classpath-classes = \
	$(call java-classes,$(classpath-sources),$(classpath-src),$(classpath-build))
classpath-object = $(build)/rt-jar.o
classpath-dep = $(classpath-build).dep

vm-classes = \
	java/internal/*.class \
	java/internal/resource/*.class

test-support-sources = \
	$(shell find $(test)/avata/ -name '*.java') \
	$(test)/ContractStaticProfile.java

# The TOS profile test set follows the admitted contract runtime, not Avata's
# old broad Java SE class-library surface.
test-sources = \
	$(test)/AllFloats.java \
	$(test)/ArrayDequeTest.java \
	$(test)/BitsetTest.java \
	$(test)/DeterministicFloatTest.java \
	$(test)/FloatConformanceVector.java \
	$(test)/PerfBaseline.java \
	$(test)/ArraysTest.java \
	$(test)/Collections.java \
	$(test)/ContractLibraryPrimitives.java \
	$(test)/ContractEntryPoint.java \
	$(test)/ContractRuntimePrimitives.java \
	$(test)/DequeHelper.java \
	$(test)/DivideByZero.java \
	$(test)/Exceptions.java \
	$(test)/Floats.java \
	$(test)/Hello.java \
	$(test)/Integers.java \
	$(test)/List.java \
	$(test)/Longs.java \
	$(test)/MonitorTest.java \
	$(test)/CoreTrapProfile.java \
	$(test)/NullPointer.java \
	$(test)/QueueHelper.java \
	$(test)/Simple.java \
	$(test)/StackOverflow.java \
	$(test)/StackTraceSourceFileTest.java \
	$(test)/Streams.java \
	$(test)/StringBuilderTest.java \
	$(test)/Strings.java \
	$(test)/StorageTest.java \
	$(test)/Switch.java \
	$(test)/Tree.java \
	$(test)/VerifierProfile.java

test-cpp-sources = $(wildcard $(test)/*.cpp)
test-sources += $(test-support-sources)
test-support-classes = $(call java-classes, $(test-support-sources),$(test),$(test-build))
test-classes = $(call java-classes,$(test-sources),$(test),$(test-build))
test-cpp-objects = $(call cpp-objects,$(test-cpp-sources),$(test),$(test-build))
test-library = $(build)/$(so-prefix)test$(so-suffix)
test-dep = $(test-build).dep

test-extra-sources = $(test)/extra/ClasspathWildcardTarget.java
test-extra-classes = \
	$(call java-classes,$(test-extra-sources),$(test),$(test-build))
test-extra-dep = $(test-build)-extra.dep
classpath-wildcard-jar = $(build)/wildcard-lib/classpath-wildcard.JAR

unittest-sources = \
	$(wildcard $(unittest)/*.cpp) \
	$(wildcard $(unittest)/util/*.cpp)

unittest-depends = \
	$(wildcard $(unittest)/*.h)

ifeq ($(target-arch),i386)
	cflags += -DAVATA_TARGET_ARCH=AVATA_ARCH_X86
endif

ifeq ($(target-arch),x86_64)
	cflags += -DAVATA_TARGET_ARCH=AVATA_ARCH_X86_64
endif

ifeq ($(target-arch),arm)
	cflags += -DAVATA_TARGET_ARCH=AVATA_ARCH_ARM
endif

ifeq ($(target-arch),arm64)
	cflags += -DAVATA_TARGET_ARCH=AVATA_ARCH_ARM64
endif

ifeq ($(target-format),elf)
	cflags += -DAVATA_TARGET_FORMAT=AVATA_FORMAT_ELF
endif

ifeq ($(target-format),pe)
	cflags += -DAVATA_TARGET_FORMAT=AVATA_FORMAT_PE
endif

ifeq ($(target-format),macho)
	cflags += -DAVATA_TARGET_FORMAT=AVATA_FORMAT_MACHO
endif

class-name = $(patsubst $(1)/%.class,%,$(2))
class-names = $(foreach x,$(2),$(call class-name,$(1),$(x)))

test-flags = -Djava.library.path=$(build) \
	-cp '$(build)/test$(target-path-separator)$(build)/extra-dir'

test-args = $(test-flags) $(input)

.PHONY: build
ifneq ($(supports_avata_executable),false)
build: $(static-library) $(executable) $(dynamic-library) \
	$(classpath-dep) $(test-dep) $(test-extra-dep) $(build)/rt.jar \
	$(build)/api.jar
else
build: $(static-library) $(dynamic-library) \
	$(classpath-dep) $(test-dep) $(test-extra-dep) $(build)/rt.jar \
	$(build)/api.jar
endif

$(test-dep): $(classpath-dep)

$(test-extra-dep): $(classpath-dep)

.PHONY: run
run: build
	$(library-path) $(test-executable) $(test-args)

.PHONY: debug
debug: build
	$(library-path) $(db) $(test-executable) $(test-args)

.PHONY: vg
vg: build
	$(library-path) $(vg) $(test-executable) $(test-args)

.PHONY: test
test: build-test run-test

.PHONY: build-test
build-test: build check-native-profile check-rt-profile check-api-profile \
	check-contract-profile-header check-api-javac check-api-java $(build)/run-tests.sh \
	$(build)/run-determinism.sh $(build)/test.sh $(build)/determinism.sh \
	$(unittest-executable) check-float-conformance

.PHONY: check-native-profile
check-native-profile: $(classpath-src)/check-native-profile.sh
	/bin/sh $(classpath-src)/check-native-profile.sh .

.PHONY: check-rt-profile
check-rt-profile: $(build)/rt.jar $(classpath-src)/check-profile.sh
	/bin/sh $(classpath-src)/check-profile.sh $(build)/rt.jar "$(JAVA_HOME)/bin/jar"

.PHONY: check-api-profile
check-api-profile: $(build)/api.jar $(classpath-src)/check-profile.sh
	/bin/sh $(classpath-src)/check-profile.sh $(build)/api.jar "$(JAVA_HOME)/bin/jar" api

.PHONY: check-contract-profile-header
check-contract-profile-header: $(build)/api.jar $(classpath-src)/generate-profile-header.sh src/avata/contract-profile.h
	@echo "checking contract profile manifest"
	@tmp="$(build)/contract-profile.h.generated" && \
	/bin/sh $(classpath-src)/generate-profile-header.sh \
		$(build)/api.jar "$(JAVA_HOME)/bin/jar" "$$tmp" && \
	if ! cmp -s "$$tmp" src/avata/contract-profile.h; then \
		echo "contract profile manifest is stale; regenerate src/avata/contract-profile.h" >&2; \
		diff -u src/avata/contract-profile.h "$$tmp" >&2 || true; \
		exit 1; \
	fi

.PHONY: check-api-javac
check-api-javac: $(build)/api.jar tools/javac
	@echo "checking api.jar bootclasspath"
	@rm -rf $(build)/api-check
	@mkdir -p $(build)/api-check/src $(build)/api-check/out
	@printf '%s\n' \
		'public final class ApiCompileCheck {' \
		'  public static long remaining() {' \
		'    return Memory.remaining();' \
		'  }' \
		'  public static String className(Object value) {' \
		'    return value.getClass().getName();' \
		'  }' \
		'}' \
		> $(build)/api-check/src/ApiCompileCheck.java
	AVATA_BUILD_DIR=$(build) AVATA_JAVAC="$(JAVA_HOME)/bin/javac" \
		tools/javac \
		-d $(build)/api-check/out \
		$(build)/api-check/src/ApiCompileCheck.java
	@printf '%s\n' \
		'import java.internal.Classes;' \
		'public final class ForbiddenInternalCompileCheck {' \
		'  Object value;' \
		'}' \
		> $(build)/api-check/src/ForbiddenInternalCompileCheck.java
	@if AVATA_BUILD_DIR=$(build) AVATA_JAVAC="$(JAVA_HOME)/bin/javac" \
		tools/javac \
		-d $(build)/api-check/out \
		$(build)/api-check/src/ForbiddenInternalCompileCheck.java \
		> $(build)/api-check/forbidden.log 2>&1; then \
		echo "api.jar check failed: javac accepted java.internal.* import" >&2; \
		cat $(build)/api-check/forbidden.log >&2; \
		exit 1; \
	fi
	@if AVATA_BUILD_DIR=$(build) AVATA_JAVAC="$(JAVA_HOME)/bin/javac" \
		tools/javac -bootclasspath $(build)/rt.jar \
		$(build)/api-check/src/ApiCompileCheck.java \
		> $(build)/api-check/override.log 2>&1; then \
		echo "api.jar check failed: tools/javac accepted bootclasspath override" >&2; \
		exit 1; \
	fi
	@printf '%s\n' \
		'public final class MutableStaticCompileCheck {' \
		'  static int value;' \
		'}' \
		> $(build)/api-check/src/MutableStaticCompileCheck.java
	@if AVATA_BUILD_DIR=$(build) AVATA_JAVAC="$(JAVA_HOME)/bin/javac" \
		tools/javac \
		-d $(build)/api-check/out \
		$(build)/api-check/src/MutableStaticCompileCheck.java \
		> $(build)/api-check/mutable-static.log 2>&1; then \
		echo "api.jar check failed: tools/javac accepted mutable static field" >&2; \
		exit 1; \
	fi
	@printf '%s\n' \
		'public final class LambdaCompileCheck {' \
		'  public static Runnable make() {' \
		'    return () -> { };' \
		'  }' \
		'}' \
		> $(build)/api-check/src/LambdaCompileCheck.java
	@if AVATA_BUILD_DIR=$(build) AVATA_JAVAC="$(JAVA_HOME)/bin/javac" \
		tools/javac \
		-d $(build)/api-check/out \
		$(build)/api-check/src/LambdaCompileCheck.java \
		> $(build)/api-check/lambda.log 2>&1; then \
		echo "api.jar check failed: tools/javac accepted invokedynamic lambda" >&2; \
		exit 1; \
	fi
	@printf '%s\n' \
		'public final class ContractEntryCompileCheck {' \
		'  @ContractEntry' \
		'  public static void transfer(boolean ok, int i, long l, Address a, Uint256 u, Bytes32 b32, Bytes4 b4, Bytes data) { }' \
		'}' \
		> $(build)/api-check/src/ContractEntryCompileCheck.java
	AVATA_BUILD_DIR=$(build) AVATA_JAVAC="$(JAVA_HOME)/bin/javac" \
		tools/javac \
		-d $(build)/api-check/out \
		$(build)/api-check/src/ContractEntryCompileCheck.java
	@printf '%s\n' \
		'public final class BadContractEntryInstanceCheck {' \
		'  @ContractEntry' \
		'  public void entry() { }' \
		'}' \
		> $(build)/api-check/src/BadContractEntryInstanceCheck.java
	@if AVATA_BUILD_DIR=$(build) AVATA_JAVAC="$(JAVA_HOME)/bin/javac" \
		tools/javac \
		-d $(build)/api-check/out \
		$(build)/api-check/src/BadContractEntryInstanceCheck.java \
		> $(build)/api-check/bad-entry-instance.log 2>&1; then \
		echo "api.jar check failed: tools/javac accepted non-static ContractEntry method" >&2; \
		exit 1; \
	fi
	@printf '%s\n' \
		'public final class BadContractEntryReturnCheck {' \
		'  @ContractEntry' \
		'  public static int entry() { return 0; }' \
		'}' \
		> $(build)/api-check/src/BadContractEntryReturnCheck.java
	@if AVATA_BUILD_DIR=$(build) AVATA_JAVAC="$(JAVA_HOME)/bin/javac" \
		tools/javac \
		-d $(build)/api-check/out \
		$(build)/api-check/src/BadContractEntryReturnCheck.java \
		> $(build)/api-check/bad-entry-return.log 2>&1; then \
		echo "api.jar check failed: tools/javac accepted non-void ContractEntry method" >&2; \
		exit 1; \
	fi
	@printf '%s\n' \
		'public final class BadContractEntryArgCheck {' \
		'  @ContractEntry' \
		'  public static void entry(String text) { }' \
		'}' \
		> $(build)/api-check/src/BadContractEntryArgCheck.java
	@if AVATA_BUILD_DIR=$(build) AVATA_JAVAC="$(JAVA_HOME)/bin/javac" \
		tools/javac \
		-d $(build)/api-check/out \
		$(build)/api-check/src/BadContractEntryArgCheck.java \
		> $(build)/api-check/bad-entry-arg.log 2>&1; then \
		echo "api.jar check failed: tools/javac accepted unsupported ContractEntry argument" >&2; \
		exit 1; \
	fi

.PHONY: check-api-java
check-api-java: $(build)/api.jar $(build)/rt.jar $(executable) tools/javac tools/java
	@echo "checking local Avata java runner"
	@rm -rf $(build)/api-run-check
	@mkdir -p $(build)/api-run-check/src $(build)/api-run-check/out
	@printf '%s\n' \
		'public final class LocalRunnerCheck {' \
		'  public static void main(String[] args) {' \
		'    System.out.println("local-runner:" + args.length + ":" + Memory.limit());' \
		'  }' \
		'}' \
		> $(build)/api-run-check/src/LocalRunnerCheck.java
	AVATA_BUILD_DIR=$(build) AVATA_JAVAC="$(JAVA_HOME)/bin/javac" \
		tools/javac \
		-d $(build)/api-run-check/out \
		$(build)/api-run-check/src/LocalRunnerCheck.java
	AVATA_BUILD_DIR=$(build) \
		tools/java \
		--gas 1000000 --memory 1048576 \
		-cp $(build)/api-run-check/out LocalRunnerCheck one two \
		> $(build)/api-run-check/runner.log
	@grep -q '^local-runner:2:1048576$$' $(build)/api-run-check/runner.log || { \
		echo "api.jar check failed: tools/java runner output mismatch" >&2; \
		cat $(build)/api-run-check/runner.log >&2; \
		exit 1; \
	}
	@if AVATA_BUILD_DIR=$(build) \
		tools/java --gas 1 --memory 1048576 \
		-cp $(build)/api-run-check/out LocalRunnerCheck \
		> $(build)/api-run-check/gas.log 2>&1; then \
		echo "api.jar check failed: tools/java low-gas execution succeeded" >&2; \
		exit 1; \
	fi
	@grep -q 'OutOfGasError' $(build)/api-run-check/gas.log || { \
		echo "api.jar check failed: tools/java low-gas run did not report OutOfGasError" >&2; \
		cat $(build)/api-run-check/gas.log >&2; \
		exit 1; \
	}
	@if AVATA_BUILD_DIR=$(build) \
		tools/java -Xbootclasspath:$(build)/api.jar \
		-cp $(build)/api-run-check/out LocalRunnerCheck \
		> $(build)/api-run-check/boot-override.log 2>&1; then \
		echo "api.jar check failed: tools/java accepted bootclasspath override" >&2; \
		exit 1; \
	fi
	@if AVATA_BUILD_DIR=$(build) \
		tools/java -Djava.library.path=/tmp \
		-cp $(build)/api-run-check/out LocalRunnerCheck \
		> $(build)/api-run-check/native-path-override.log 2>&1; then \
		echo "api.jar check failed: tools/java accepted java.library.path override" >&2; \
		exit 1; \
	fi

.PHONY: check-float-conformance
check-float-conformance: $(build)/test/FloatConformanceVector.class $(executable)
	@echo "checking float conformance vector"
	@cd $(build) && LD_LIBRARY_PATH=. ./avata \
		-Djava.library.path=. -cp test:extra-dir FloatConformanceVector \
		> float-conformance-actual.txt 2>/dev/null
	@diff $(test)/float-conformance-reference.txt $(build)/float-conformance-actual.txt || { \
		echo "FAIL: float conformance vector mismatch — platform divergence detected" >&2; \
		exit 1; \
	}
	@echo "float conformance: ok"

# Measure interpreter throughput for the representative PerfBaseline workload.
# The checksum is deterministic (no floating-point, no timing); check-perf-baseline
# compares it against test/perf-baseline-reference.txt and fails the build if it
# changes, signalling an opcode-gas or dispatch regression.
.PHONY: perf-baseline
perf-baseline: $(build)/test/PerfBaseline.class $(build)/rt.jar $(build)/api.jar $(executable)
	@echo "running perf baseline — $(build)/test/PerfBaseline.class"
	AVATA_BUILD_DIR=$(build) tools/java \
		--gas 10000000 --memory 4194304 \
		-cp $(build)/test PerfBaseline

.PHONY: check-perf-baseline
check-perf-baseline: $(build)/test/PerfBaseline.class $(build)/rt.jar $(build)/api.jar $(executable)
	@echo "checking perf baseline checksum"
	@AVATA_BUILD_DIR=$(build) tools/java \
		--gas 10000000 --memory 4194304 \
		-cp $(build)/test PerfBaseline \
		> $(build)/perf-baseline-actual.txt 2>/dev/null
	@diff $(test)/perf-baseline-reference.txt $(build)/perf-baseline-actual.txt || { \
		echo "FAIL: perf baseline checksum changed — opcode-gas or dispatch regression" >&2; \
		echo "  expected: $$(cat $(test)/perf-baseline-reference.txt)" >&2; \
		echo "  actual:   $$(cat $(build)/perf-baseline-actual.txt)" >&2; \
		echo "  if this is an intentional gas-schedule change, update test/perf-baseline-reference.txt" >&2; \
		exit 1; \
	}
	@echo "perf-baseline: ok"

# Regenerate reference when the gas schedule is intentionally changed.
.PHONY: regen-perf-baseline
regen-perf-baseline: $(build)/test/PerfBaseline.class $(build)/rt.jar $(build)/api.jar $(executable)
	@echo "regenerating perf-baseline-reference.txt"
	AVATA_BUILD_DIR=$(build) tools/java \
		--gas 10000000 --memory 4194304 \
		-cp $(build)/test PerfBaseline \
		> $(test)/perf-baseline-reference.txt
	@echo "perf-baseline-reference.txt updated — review and commit"

# Run this to update the reference when the SoftFloat engine or opcode
# semantics intentionally change.  Commit the new reference after review.
.PHONY: regen-float-conformance
regen-float-conformance: $(build)/test/FloatConformanceVector.class $(executable)
	@echo "regenerating float-conformance-reference.txt"
	@cd $(build) && LD_LIBRARY_PATH=. ./avata \
		-Djava.library.path=. -cp test:extra-dir FloatConformanceVector \
		> float-conformance-reference-tmp.txt 2>/dev/null
	@cp $(build)/float-conformance-reference-tmp.txt $(test)/float-conformance-reference.txt
	@echo "written: $(test)/float-conformance-reference.txt"

.PHONY: run-test
run-test: build-test
ifneq ($(remote-test),true)
	/bin/sh $(build)/run-tests.sh
	/bin/sh $(build)/run-determinism.sh
	$(MAKE) check-perf-baseline
else
	@echo "running tests on $(remote-test-user)@$(remote-test-host):$(remote-test-port), in $(remote-test-dir)"
	rsync $(build) -rav --exclude '*.o' --rsh="ssh -p$(remote-test-port)" $(remote-test-user)@$(remote-test-host):$(remote-test-dir)
	ssh -p$(remote-test-port) $(remote-test-user)@$(remote-test-host) sh "$(remote-test-dir)/$(platform)-$(arch)$(options)/run-tests.sh"
	ssh -p$(remote-test-port) $(remote-test-user)@$(remote-test-host) sh "$(remote-test-dir)/$(platform)-$(arch)$(options)/run-determinism.sh"
endif

.PHONY: tarball
tarball:
	@echo "creating build/avata-$(version).tar.bz2"
	@mkdir -p build
	(cd .. && tar --exclude=build --exclude=cmake-build --exclude=distrib \
		--exclude=lib --exclude='.*' --exclude='*~' \
		-cjf avata/build/avata-$(version).tar.bz2 avata)

.PHONY: clean-current
clean-current:
	@echo "removing $(build)"
	rm -rf $(build)

.PHONY: clean
clean:
	@echo "removing build directories"
	rm -rf build cmake-build distrib lib

$(build)/run-tests.sh: $(test-classes) makefile $(build)/extra-dir/multi-classpath-test.txt $(build)/test/multi-classpath-test.txt $(classpath-wildcard-jar)
	echo 'cd $$(dirname $$0)' > $(@)
	echo "sh ./test.sh 2>/dev/null \\" >> $(@)
	echo "$(shell echo $(library-path) | sed 's|$(build)|\.|g') ./$(name)-unittest${exe-suffix} ./$(notdir $(test-executable)) $(mode) \"-Djava.library.path=. -cp test$(target-path-separator)extra-dir\" \\" >> $(@)
	echo "$(call class-names,$(test-build),$(filter-out $(test-support-classes), $(test-classes))) \\" >> $(@)
	echo "" >> $(@)

$(build)/jdk-run-tests.sh: $(test-classes) makefile $(build)/extra-dir/multi-classpath-test.txt $(build)/test/multi-classpath-test.txt
	echo 'cd $$(dirname $$0)' > $(@)
	echo "sh ./test.sh 2>/dev/null \\" >> $(@)
	echo "'' true $(JAVA_HOME)/bin/java $(mode) \"-Xmx128m -Djava.library.path=. -cp test$(path-separator)extra-dir$(path-separator)rt\" \\" >> $(@)
	echo "$(call class-names,$(test-build),$(filter-out $(test-support-classes), $(test-classes))) \\" >> $(@)
	echo "" >> $(@)

$(build)/run-determinism.sh: $(test-classes) makefile $(build)/determinism.sh $(build)/extra-dir/multi-classpath-test.txt $(build)/test/multi-classpath-test.txt $(classpath-wildcard-jar)
	echo 'cd $$(dirname $$0)' > $(@)
	echo "sh ./determinism.sh 2>/dev/null \\" >> $(@)
	echo "$(shell echo $(library-path) | sed 's|$(build)|\.|g') ./$(notdir $(test-executable)) $(mode) \"-Djava.library.path=. -cp test$(target-path-separator)extra-dir\" \\" >> $(@)
	echo "$(call class-names,$(test-build),$(filter-out $(test-support-classes), $(test-classes))) \\" >> $(@)
	echo "" >> $(@)

$(build)/extra-dir/multi-classpath-test.txt:
	mkdir -p $(build)/extra-dir
	echo "$@" > $@

$(build)/test/multi-classpath-test.txt:
	mkdir -p $(build)/test
	echo "$@" > $@

$(classpath-wildcard-jar): $(test-extra-dep)
	mkdir -p $(dir $@)
	$(jar) cf $(@) -C $(test-build) extra/ClasspathWildcardTarget.class

$(build)/test.sh: $(test)/test.sh
	cp $(<) $(@)

$(build)/determinism.sh: $(test)/determinism.sh
	cp $(<) $(@)

gen-arg = $(shell echo $(1) | sed -e 's:$(build)/type-\(.*\)\.cpp:\1:')
$(generated-code): %.cpp: $(src)/types.def $(generator) $(classpath-dep)
	@echo "generating $(@)"
	@mkdir -p $(dir $(@))
	$(generator) -cp $(boot-classpath) -i $(<) -o $(@) -t $(call gen-arg,$(@))

$(classpath-dep): $(classpath-sources) $(classpath-jar-dep)
	@echo "compiling classpath classes"
	@rm -rf $(classpath-build)
	@mkdir -p $(classpath-build)
	$(javac) -source 1.$(java-version) -target 1.$(java-version) \
		-d $(classpath-build) -bootclasspath $(boot-classpath) \
		$(classpath-sources)
	@touch $(@)

$(test-build)/%.class: $(test)/%.java
	@echo $(<)

$(test-dep): $(test-sources) $(test-library)
	@echo "compiling test classes"
	@mkdir -p $(test-build)
	files="$(shell $(MAKE) -s --no-print-directory build=$(build) $(test-classes))"; \
	if test -n "$${files}"; then \
		$(javac) -source 1.$(java-version) -target 1.$(java-version) \
			-classpath $(test-build) -d $(test-build) -bootclasspath $(boot-classpath) $${files}; \
	fi
	@touch $(@)

$(test-extra-dep): $(test-extra-sources)
	@echo "compiling extra test classes"
	@mkdir -p $(test-build)
	files="$(shell $(MAKE) -s --no-print-directory build=$(build) $(test-extra-classes))"; \
	if test -n "$${files}"; then \
		$(javac) -source 1.$(java-version) -target 1.$(java-version) \
			-d $(test-build) -bootclasspath $(boot-classpath) $${files}; \
	fi
	@touch $(@)

define compile-object
	@echo "compiling $(@)"
	@mkdir -p $(dir $(@))
	$(cxx) $(cflags) -c $$($(windows-path) $(<)) $(call output,$(@))
endef

define compile-softfloat-object
	@echo "compiling $(@)"
	@mkdir -p $(dir $(@))
	$(cc) $(softfloat-cflags) -c $$($(windows-path) $(<)) $(call output,$(@))
endef

define compile-asm-object
	@echo "compiling $(@)"
	@mkdir -p $(dir $(@))
	$(as) $(asmflags) $(call asm-output,$(@)) $(call asm-input,$(<))
endef

define compile-unittest-object
	@echo "compiling $(@)"
	@mkdir -p $(dir $(@))
	$(cxx) $(cflags) -c $$($(windows-path) $(<)) -I$(unittest) $(call output,$(@))
endef

$(vm-cpp-objects): $(build)/%.o: $(src)/%.cpp $(vm-depends)
	$(compile-object)

$(softfloat-objects): $(build)/%.o: $(src)/%.c $(vm-depends)
	$(compile-softfloat-object)

$(unittest-objects): $(build)/unittest/%.o: $(unittest)/%.cpp $(vm-depends) $(unittest-depends)
	$(compile-unittest-object)

$(test-cpp-objects): $(test-build)/%.o: $(test)/%.cpp $(vm-depends)
	$(compile-object)

$(test-library): $(test-cpp-objects)
	@echo "linking $(@)"
ifdef ms_cl_compiler
	$(ld) $(shared) $(lflags) $(^) -out:$(@) \
		-debug -PDB:$(subst $(so-suffix),.pdb,$(@)) \
		-IMPLIB:$(test-build)/$(name).lib $(manifest-flags)
ifdef mt
	$(mt) -nologo -manifest $(@).manifest -outputresource:"$(@);2"
endif
else
	$(ld) $(^) $(shared) $(lflags) -o $(@)
endif

$(vm-asm-objects): $(build)/%-asm.o: $(src)/%.$(asm-format)
	$(compile-asm-object)

$(heapwalk-objects): $(build)/%.o: $(src)/%.cpp $(vm-depends)
	$(compile-object)

$(driver-object): $(driver-source)
	$(compile-object)

$(build)/main-dynamic.o: $(driver-source)
	@echo "compiling $(@)"
	@mkdir -p $(dir $(@))
	$(cxx) $(cflags) -DBOOT_LIBRARY=\"$(so-prefix)jvm$(so-suffix)\" \
		-c $(<) $(call output,$(@))

$(boot-object): $(boot-source)
	$(compile-object)

$(object-writer-objects) $(binary-to-object-objects): $(build)/%.o: $(src)/%.cpp $(binary-to-object-depends) $(object-writer-depends) $(all-depends)
	@mkdir -p $(dir $(@))
	$(build-cxx) $(converter-cflags) -c $(<) -o $(@)

$(converter): $(converter-objects) $(converter-tool-objects)
	@mkdir -p $(dir $(@))
	$(build-cc) $(^) -g -o $(@)

$(build)/rt.jar: $(classpath-dep) $(classpath-jar-dep)
	@echo "creating $(@)"
	(wd=$$(pwd) && \
	 cd $(classpath-build) && \
	 $(jar) c0f "$$($(native-path) "$${wd}/$(@)")" .)

$(build)/api.jar: $(classpath-dep) $(classpath-jar-dep)
	@echo "creating $(@)"
	(wd=$$(pwd) && \
	 cd $(classpath-build) && \
	 files=$$(find . -type f ! -path './java/internal/*' -print | sed 's#^\./##') && \
	 $(jar) c0f "$$($(native-path) "$${wd}/$(@)")" $$files)

$(classpath-object): $(build)/rt.jar $(converter)
	@echo "creating $(@)"
	$(converter) $(<) $(@) _binary_classpath_jar_start \
		_binary_classpath_jar_end $(target-format) $(arch)

define compile-generator-object
	@echo "compiling $(@)"
	@mkdir -p $(dir $(@))
	$(build-cxx) -DPOINTER_SIZE=$(pointer-size) -O0 -g3 $(build-cflags) \
		-c $(<) -o $(@)
endef

$(generator-objects): $(generator-depends)
$(generator-objects): $(build)/%-build.o: $(src)/%.cpp
	$(compile-generator-object)

$(jni-objects): $(build)/%.o: $(classpath-src)/%.cpp $(vm-depends)
	$(compile-object)

$(static-library): $(vm-objects) $(classpath-objects) $(vm-heapwalk-objects)
	@echo "creating $(@)"
	@rm -rf $(build)/libavata
	@mkdir -p $(build)/libavata
	rm -rf $(@)
	for x in $(^); \
		do cp $${x} $(build)/libavata/$$(echo $${x} | sed s:/:_:g); \
	done
ifdef ms_cl_compiler
	$(ar) $(arflags) $(build)/libavata/*.o -out:$(@)
else
	$(ar) cru $(@) $(build)/libavata/*.o
	$(ranlib) $(@)
endif

executable-objects = $(vm-objects) $(classpath-objects) $(driver-object) \
	$(vm-heapwalk-objects) $(boot-object) $(vm-classpath-objects)

unittest-executable-objects = $(unittest-objects) $(vm-objects) \
	$(classpath-objects) $(vm-heapwalk-objects)

# apparently, make does poorly with ifs inside of defines, and indented defines.
# I suggest re-indenting the following before making edits (and unindenting afterwards):
ifneq ($(platform),windows)
define link-executable
	@echo linking $(@)
	$(ld) $(^) $(rdynamic) $(lflags) -o $(@)
endef
else
ifdef ms_cl_compiler
ifdef mt
define link-executable
	@echo linking $(@)
	$(ld) $(lflags) $(^) -out:$(@) \
		-debug -PDB:$(subst $(exe-suffix),.pdb,$(@)) $(manifest-flags)
	$(mt) -nologo -manifest $(@).manifest -outputresource:"$(@);1"
endef
else
define link-executable
	@echo linking $(@)
	$(mt) -nologo -manifest $(@).manifest -outputresource:"$(@);1"
endef
endif
else
define link-executable
	@echo linking $(@)
	$(dlltool) -z $(@).def $(^)
	$(dlltool) -d $(@).def -e $(@).exp
	$(ld) $(@).exp $(^) $(lflags) -o $(@)
endef
endif
endif

$(executable): $(executable-objects)
	$(link-executable)

$(unittest-executable): $(unittest-executable-objects)
	$(link-executable)

$(dynamic-library): $(vm-objects) $(classpath-objects) \
		$(vm-heapwalk-objects) $(boot-object) $(vm-classpath-objects)
	@echo "linking $(@)"
ifdef ms_cl_compiler
	$(ld) $(shared) $(lflags) $(^) -out:$(@) \
		-debug -PDB:$(subst $(so-suffix),.pdb,$(@)) \
		-IMPLIB:$(subst $(so-suffix),.lib,$(@)) $(manifest-flags)
ifdef mt
	$(mt) -nologo -manifest $(@).manifest -outputresource:"$(@);2"
endif
else
	$(ld) $(^) $(version-script-flag) $(soname-flag) \
		$(shared) $(lflags) -o $(@)
endif
	$(strip) $(strip-all) $(@)

# todo: the $(no-lto) flag below is due to odd undefined reference errors on
# Ubuntu 11.10 which may be fixable without disabling LTO.
$(executable-dynamic): $(driver-dynamic-objects) $(dynamic-library)
	@echo "linking $(@)"
ifdef ms_cl_compiler
	$(ld) $(lflags) -LIBPATH:$(build) -DEFAULTLIB:$(name) \
		-debug -PDB:$(subst $(exe-suffix),.pdb,$(@)) \
		$(driver-dynamic-objects) -out:$(@) $(manifest-flags)
ifdef mt
	$(mt) -nologo -manifest $(@).manifest -outputresource:"$(@);1"
endif
else
	$(ld) $(driver-dynamic-objects) -L$(build) -ljvm $(lflags) $(no-lto) $(rpath) -o $(@)
endif
	$(strip) $(strip-all) $(@)

$(generator): $(generator-objects)
	@echo "linking $(@)"
	$(build-ld-cpp) $(^) $(build-lflags) $(static-on-windows) -o $(@)
