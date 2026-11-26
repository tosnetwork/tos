if (NOT GSL_FOUND)
  find_package(GSL)
endif()
if (NOT BLAS_FOUND)
  find_package(BLAS)
endif()

set(RLDP_SOURCE
  Ack.cpp
  Bbr.cpp
  BdwStats.cpp
  FecHelper.cpp
  InboundTransfer.cpp
  LossSender.cpp
  LossStats.cpp
  OutboundTransfer.cpp
  Pacer.cpp
  rldp.cpp
  RldpReceiver.cpp
  RldpSender.cpp
  RldpConnection.cpp
  RttStats.cpp
  SenderPackets.cpp

  Ack.h
  Bbr.h
  BdwStats.h
  FecHelper.h
  InboundTransfer.h
  rldp-inbound-budget.h
  LossSender.h
  LossStats.h
  OutboundTransfer.h
  Pacer.h
  rldp.h
  rldp.hpp
  RldpReceiver.h
  RldpSender.h
  RldpConnection.h
  RttStats.h
  SenderPackets.h
)

add_library(rldp2 STATIC ${RLDP_SOURCE})

if (GSL_FOUND AND BLAS_FOUND)
  if (TOS_STATIC_GSL)
    # The GSL soname changes between distribution releases, so a binary that
    # should load on more than the one it was built on carries the archive.
    # The CBLAS symbols it may need still come from the shared BLAS.
    get_filename_component(TOS_GSL_LIBRARY_DIR "${GSL_LIBRARY}" DIRECTORY)
    find_library(TOS_GSL_STATIC_LIBRARY NAMES libgsl.a HINTS "${TOS_GSL_LIBRARY_DIR}" NO_DEFAULT_PATH)
    if (NOT TOS_GSL_STATIC_LIBRARY)
      message(FATAL_ERROR "TOS_STATIC_GSL is ON, but there is no libgsl.a next to ${GSL_LIBRARY}")
    endif()
    target_link_libraries(rldp2 PRIVATE ${TOS_GSL_STATIC_LIBRARY} blas)
  else()
    target_link_libraries(rldp2 PRIVATE gsl blas)
  endif()
  target_compile_definitions(rldp2 PRIVATE -DTOS_HAVE_GSL=1)
elseif (TOS_STATIC_GSL)
  message(FATAL_ERROR "TOS_STATIC_GSL is ON, but GSL or BLAS was not found")
endif()
target_link_libraries(rldp2 PUBLIC tdutils tdactor fec adnl tl_api)

