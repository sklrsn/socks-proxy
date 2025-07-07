// Copyright 2025
// Licensed under the  Apache License

package socks

const (
	// SOCKS Protocol Versions
	SOCKS5_VERSION = 0x05
	SOCKS4_VERSION = 0x04

	// Authentication Methods (RFC 1928)
	AUTH_NO_AUTH       = 0x00 // No authentication required
	AUTH_GSSAPI        = 0x01 // GSSAPI
	AUTH_USERNAME_PASS = 0x02 // Username/password
	AUTH_IANA_START    = 0x03 // IANA assigned methods start
	AUTH_IANA_END      = 0x7F // IANA assigned methods end
	AUTH_PRIVATE_START = 0x80 // Private methods start
	AUTH_PRIVATE_END   = 0xFE // Private methods end
	AUTH_NO_METHODS    = 0xFF // No acceptable methods

	// Username/Password Authentication Version
	USERPASS_VERSION = 0x01

	// Username/Password Authentication Status
	USERPASS_SUCCESS = 0x00
	USERPASS_FAILURE = 0x01

	// SOCKS5 Commands
	CMD_CONNECT       = 0x01 // CONNECT
	CMD_BIND          = 0x02 // BIND
	CMD_UDP_ASSOCIATE = 0x03 // UDP ASSOCIATE

	// Address Types
	ATYP_IPV4   = 0x01 // IPv4 address
	ATYP_DOMAIN = 0x03 // Domain name
	ATYP_IPV6   = 0x04 // IPv6 address

	// Reply Codes
	REP_SUCCESS               = 0x00 // Succeeded
	REP_GENERAL_FAILURE       = 0x01 // General SOCKS server failure
	REP_NOT_ALLOWED           = 0x02 // Connection not allowed by ruleset
	REP_NETWORK_UNREACHABLE   = 0x03 // Network unreachable
	REP_HOST_UNREACHABLE      = 0x04 // Host unreachable
	REP_CONNECTION_REFUSED    = 0x05 // Connection refused
	REP_TTL_EXPIRED           = 0x06 // TTL expired
	REP_COMMAND_NOT_SUPPORTED = 0x07 // Command not supported
	REP_ADDRESS_NOT_SUPPORTED = 0x08 // Address type not supported

	// Reserved Field Value
	RSV = 0x00 // Reserved field value

	// Protocol Limits
	MAX_METHODS      = 255 // Maximum number of auth methods
	MAX_USERNAME_LEN = 255 // Maximum username length
	MAX_PASSWORD_LEN = 255 // Maximum password length
	MAX_DOMAIN_LEN   = 255 // Maximum domain name length

	// Message Sizes
	AUTH_REQUEST_MIN_SIZE    = 3  // Minimum auth request size (VER + NMETHODS + 1 METHOD)
	AUTH_RESPONSE_SIZE       = 2  // Auth response size (VER + METHOD)
	USERPASS_MIN_SIZE        = 5  // Minimum username/password size (VER + ULEN + USER + PLEN + PASS)
	CONNECT_REQUEST_MIN_SIZE = 10 // Minimum connect request size

	// IPv4/IPv6 Address Sizes
	IPV4_SIZE = 4  // IPv4 address size in bytes
	IPV6_SIZE = 16 // IPv6 address size in bytes
	PORT_SIZE = 2  // Port size in bytes
)
