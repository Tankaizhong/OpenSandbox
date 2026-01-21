package policy

const (
	EgressServerAddrEnv     = "OPENSANDBOX_EGRESS_HTTP_ADDR"
	DefaultEgressServerAddr = ":18080"

	EgressAuthTokenEnv    = "OPENSANDBOX_EGRESS_TOKEN"
	EgressAuthTokenHeader = "OPENSANDBOX-EGRESS-AUTH"
)
