package chaincode

import (
	"regexp"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	cb "github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/gossip"
	"github.com/spf13/cobra"
	"github.com/xixuejia/digital-wallet/fabric/gosdk/chaincode/utils"
	hfrdcommon "github.com/xixuejia/digital-wallet/fabric/gosdk/common"
)

var chaincodeCmd = &cobra.Command{
	Use:              "chaincode",
	Short:            "cc related operations, install | instantiate | invoke",
	Long:             "cc related operations, install on peers | instantiate on channels| invoke instantiated cc",
	TraverseChildren: true,
}

var (
	chaincodeNamePrefix   string
	channelNamePrefix     string
	prefixOffset          int
	channelNameList       []string
	chaincodeVersion      string
	path                  string
	peers                 []string
	channelName           string
	org                   string
	chaincodeName         string
	queryOnly             string
	chaincodeParams       string
	staticTransientMap    string
	dynamicTransientMapKs []string
	dynamicTransientMapVs []string
	threads               int
	policystr             string
	collectionsConfigPath string // collections-config file , used to define private data
	connection            *hfrdcommon.ConnectionProfile
	fabricVersion         string
	prometheusTargetUrl   string
	lang                  string
)

const (
	PEERS_IN_CHANNEL    = "channels.%s.peers"   // defined in sdk-go config yaml file
	CLIENT_ORGANIZATION = "client.organization" // defined in fabric-sdk-go config yaml

	// cli parameters
	CC_NAME_PREFIX            = "chaincodeNamePrefix"
	CHAN_NAME_PREFIX          = "channelNamePrefix"
	PREFIX_OFFSET             = "prefixOffset"
	CHAN_NAME_LIST            = "channelNameList"
	CC_VERSION                = "chaincodeVersion"
	CC_PATH                   = "path"
	PEERS                     = "peers"
	CHANNEL_NAME              = "channelName"
	CC_NAME                   = "chaincodeName"
	QUERY_ONLY                = "queryOnly"
	CC_PARAMS                 = "chaincodeParams"
	CC_STATIC_TRANSIENTMAP    = "staticTransientMap"
	CC_DYNAMIC_TRANSIENTMAP_K = "dynamicTransientMapKs"
	CC_DYNAMIC_TRANSIENTMAP_V = "dynamicTransientMapVs"
	THREADS                   = "threads"
	POLICY_STR                = "policyStr"
	COLLECTION_CONFIG_PATH    = "collectionsConfigPath"
	FABRIC_VERSION            = "fabricVersion"
	PROMETHEUS_TARGET_URL     = "prometheusTargetUrl"

	// keys in connection profile
	CP_PEERS = "peers"
	CP_ORGS  = "organizations"
)

// Cmd returns the cobra command for Chaincode
func Cmd() *cobra.Command {
	chaincodeCmd.AddCommand(installCmd())
	chaincodeCmd.AddCommand(instantiateCmd())
	chaincodeCmd.AddCommand(invokeCmd())
	return chaincodeCmd
}

type Chaincode struct {
	*hfrdcommon.Base
	namePrefix        string            // Chaincode NamePrefix for install/instantiate
	name              string            // Chaincode name for invoke/query
	args              []string          // Arguments for invoke/query
	transientMap      map[string][]byte // Chaincode transient map. Used in private data chaincodes
	version           string            // chaincode version
	path              string            // chaincode path on file system: relative to GOPATH env variable
	channel           string            // on which channel to instantiate the chaincode
	channelPrefix     string            // channel name prefix for instantiate cc operation
	sdk               *fabsdk.FabricSDK // the fabric-sdk-go instance to interact with fabric network
	client            *channel.Client   // the client to send chaincode invoke request
	invokeClient      *utils.Client     // our customized client to send chaincode invoke w/ ability to break down latency
	queryOnly         bool
	CollectionsConfig []*cb.CollectionConfig // Collections config used to instantiate pvt(private data) chaincode
}
type endorser struct {
	Url        string
	MspId      string
	TlsCACerts map[string]string
}

// Given the peersMap from connection profile and the peer name
// Return peerUrl of the peerName if found and true
// OR
// Return empty string and false if not found
func getPeerUrl(peersMap interface{}, peerName string) (string, bool) {
	if peersMap, ok := peersMap.(map[string]interface{}); ok {
		if peerMap, ok := peersMap[peerName]; ok {
			if peerMap, ok := peerMap.(map[string]interface{}); ok {
				if peerUrl, ok := peerMap["url"]; ok {
					if peerUrl, ok := peerUrl.(string); ok {
						return peerUrl, true
					}
				}
			}
		}
	}
	return "", false
}

func getPeerSubstitutionUrl(peerMatchers interface{}, peerUrl string) (string, bool) {
	if peerMatchers, ok := peerMatchers.([]interface{}); ok {
		for _, peerMatcher := range peerMatchers {
			if peerMatcher, ok := peerMatcher.(map[interface{}]interface{}); ok {
				if pattern, ok := peerMatcher["pattern"]; ok {
					if pattern, ok := pattern.(string); ok && len(pattern) > 0 {
						if match, _ := regexp.MatchString(pattern, peerUrl); match {
							if urlSubExp, ok := peerMatcher["urlSubstitutionExp"]; ok {
								if urlSubExp, ok := urlSubExp.(string); ok {
									return urlSubExp, true
								}

							}
						}
					}
				}
			}
		}
	}
	return "", false
}

func getPeerEndpoint(env *gossip.SignedGossipMessage) string {
	if env == nil {
		return ""
	}
	aliveMsg, _ := env.ToGossipMessage()
	if aliveMsg == nil {
		return ""
	}
	if !aliveMsg.IsAliveMsg() || aliveMsg.GetAliveMsg().Membership == nil {
		return ""
	}
	return aliveMsg.GetAliveMsg().Membership.Endpoint
}
