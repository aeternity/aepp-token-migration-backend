package merkletree

import (
	"encoding/json"
	"fmt"
)

// Node represents a single node in a Merkle tree
type Node interface {
	fmt.Stringer
	Hash() string
	Index() int
}

// MerkleTree defines and represents the methods a generic Merkle tree should have
type MerkleTree interface {
	fmt.Stringer
	Add(data []byte) (index int, hash string)
	IntermediaryHashesByIndex(index int) (intermediaryHashes []string, err error)
	ValidateExistence(original []byte, index int, intermediaryHashes []string) (bool, error)
	HashAt(index int) (string, error)
	Root() string
	Length() int
}

type internaler interface {
	Insert(hash string) (index int)
	RawInsert(hash string) (index int, leaf Node)
	Recalculate() (root string)
}

// InternalMerkleTree defines additional functions that are not supposed to be exposed to outside user to call.
// These functions deal with direct inserts of hashes and tree recalculation
type InternalMerkleTree interface {
	MerkleTree
	internaler
}

type externaler interface {
	json.Marshaler
}

// ExternalMerkleTree defines additional functions that are to be exported when the tree is communicated with the outside world.
type ExternalMerkleTree interface {
	MerkleTree
	externaler
}

// FullMerkleTree is both Internal and External
type FullMerkleTree interface {
	MerkleTree
	internaler
	externaler
}

// MigrationInfo is a token owner info
type MigrationInfo struct {
	Eth_address     string
	Hash            string
	Leaf_index      int
	Balance         string
	Ae_address      string
	Migrated        int
	Migrate_tx_hash string
}

type ContractTxInfoWrapper struct {
	CallInfo struct {
		CallerId    string   `json:"caller_id"`
		CallerNonce int   `json:"caller_nonce"`
		ContractId  string   `json:"contract_id"`
		GasPrice    int   `json:"gas_price"`
		GasUsed     int   `json:"gas_used"`
		Height      int      `json:"height"`
		//Log         []string `json:"log"`
		ReturnType  string   `json:"return_type"`
		ReturnValue string   `json:"return_value"`
	} `json:"call_info"`
}

// ContractTxInfo show deploy info
type ContractTxInfo struct {
	CallerId    string   `json:"caller_id"`
	CallerNonce string   `json:"caller_nonce"`
	ContractId  string   `json:"contract_id"`
	GasPrice    string   `json:"gas_price"`
	GasUsed     string   `json:"gas_used"`
	Height      int      `json:"height"`
	Log         []string `json:"log"`
	ReturnType  string   `json:"return_type"`
	ReturnValue string   `json:"return_value"`
}

type BackendlessConfig struct {
	ID string
	Key string
	Url string
	UserToken string
	Login    string `json:"login"`
	Password string `json:"password"`
	Table string
}

// connectionString, port, secretKey, contractRawUrl, aeContractAddress, aeNodeUrl
type EnvConfig struct {
	DbConnectionStr string
	BackendlessConfig
	Port int
	SecretKey string
	ContractRawUrl string
	AEContractAddress string
	AENodeUrl string
	AENetworkID string
	AEBackend string
	AEAbiVersion uint16
}
