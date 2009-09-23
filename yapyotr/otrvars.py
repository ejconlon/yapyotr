# Part of yapyotr - copyright 2009 Eric Conlon
# Licensed under the GPLv3
# ejconlon@gmail.com | http://it.fuelsyourcyb.org

OtrOptions = {
	"ALLOW_V1": False,
	"ALLOW_V2": True,
	"REQUIRE_ENCRYPTION": False,
	"SEND_WHITESPACE_TAG": False,
	"WHITESPACE_START_AKE": False,
	"ERROR_START_AKE": False
}
OtrConstants = {
	"whitespace_base": " \t  \t\t\t\t \t \t \t  ",
	"whitespace_v1": " \t \t  \t ",
	"whitespace_v2": "  \t\t  \t ",
	"text_base": "?OTR",
	"text_encoded": "?OTR:",
	"text_dh_commit": "?OTR:AAIC",
	"text_dh_key": "?OTR:AAIK",
	"text_reveal_sig": "?OTR:AAIR",
	"text_signature": "?OTR:AAIS",
	"text_error": "?OTR Error:",
	"text_query_1": "?OTR?",
	"text_query_2": "?OTRv",
	"text_data_1": "?OTR:AAED",
	"text_data_2": "?OTR:AAID",
	"text_v1_key_exch": "?OTR:AAEK",
	"code_dh_commit": 0x02,
	"code_data": 0x03,
	"code_dh_key": 0x0a,
	"code_reveal_sig": 0x11,
	"code_signature": 0x12,
	"code_error": 0xff,
	"code_query": 0x100,
	"code_plaintext": 0x102,
	"code_unknown": 0x110,
	"code_v1_key_exch": 0x103,
	"version_2_bytes": (0, 2),
	"dsa_code_bytes": (0, 0)
}

# just an empty namespace
class EmptyMemo:
	pass
memo = EmptyMemo()
