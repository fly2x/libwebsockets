#
# libwebsockets - openHiTLS backend CMake configuration
#

# Check required headers
if (NOT EXISTS "${LWS_OPENHITLS_INCLUDE_DIRS}/hitls/tls/hitls.h")
	message(FATAL_ERROR "openHiTLS header not found: ${LWS_OPENHITLS_INCLUDE_DIRS}/hitls/tls/hitls.h")
endif()

# Include directories
include_directories(${LWS_OPENHITLS_INCLUDE_DIRS})
# Add openHiTLS subdirectories for internal headers (bsl_obj.h, etc.)
include_directories(${LWS_OPENHITLS_INCLUDE_DIRS}/hitls/bsl)
include_directories(${LWS_OPENHITLS_INCLUDE_DIRS}/hitls/tls)
include_directories(${LWS_OPENHITLS_INCLUDE_DIRS}/hitls/crypto)
include_directories(${LWS_OPENHITLS_INCLUDE_DIRS}/hitls/pki)

# Source files - use SOURCES variable for exports_to_parent_scope() to work
list(APPEND SOURCES
	tls/openhitls/openhitls-tls.c
	tls/openhitls/openhitls-ssl.c
	tls/openhitls/openhitls-x509.c
	tls/openhitls/openhitls-session.c
	tls/openhitls/lws-genhash.c
)

# Add server-side if not disabled
if (NOT LWS_WITHOUT_SERVER)
	list(APPEND SOURCES tls/openhitls/openhitls-server.c)
endif()

# Add client-side if not disabled
if (NOT LWS_WITHOUT_CLIENT)
	list(APPEND SOURCES tls/openhitls/openhitls-client.c)
endif()

# Crypto operations (if needed for JOSE/COSE support)
if (LWS_WITH_GENCRYPTO)
	list(APPEND SOURCES
		tls/openhitls/lws-genaes.c
		tls/openhitls/lws-gencrypto.c
		tls/openhitls/lws-genrsa.c
		tls/openhitls/lws-genec.c
	)
	# Note: RSA/EC implementations provide basic functionality for JOSE.
	# Some advanced features (key generation, multiple padding modes) are
	# marked as TODO and can be enhanced as needed.
endif()

# Export to parent scope
exports_to_parent_scope()
