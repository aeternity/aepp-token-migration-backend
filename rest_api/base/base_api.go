package baseapi

import (
	"aepp-sdk-go/aeternity"
	"aepp-sdk-go/utils"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"

	// "github.com/LimeChain/merkletree"
	// merkletree "aepp-token-migration-backend/memory_merkle_tree"
	postgre "aepp-token-migration-backend/postgre_sql"
	merkletree "aepp-token-migration-backend/types"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

// MerkleTreeStatus takes pointer to initialized router and the merkle tree and exposes Rest API routes for getting of status
func MerkleTreeStatus(treeRouter chi.Router, tree merkletree.ExternalMerkleTree) chi.Router {
	treeRouter.Get("/", getTreeStatus(tree))
	return treeRouter
}

// MerkleTreeHashes takes pointer to initialized router and the merkle tree and exposes Rest API routes for getting of intermediary hashes
func MerkleTreeHashes(treeRouter chi.Router, tree merkletree.ExternalMerkleTree) chi.Router {
	treeRouter.Get("/siblings/{index}", getIntermediaryHashesHandler(tree))
	return treeRouter
}

// MerkleTreeInsert takes pointer to initialized router and the merkle tree and exposes Rest API routes for addition
func MerkleTreeInsert(treeRouter chi.Router, tree merkletree.ExternalMerkleTree) chi.Router {
	treeRouter.Post("/", addDataHandler(tree))
	return treeRouter
}

// MerkleAPIResponse represents the minimal response structure
type MerkleAPIResponse struct {
	Status bool   `json:"status"`
	Error  string `json:"error,omitempty"`
}

type treeStatusResponse struct {
	MerkleAPIResponse
	Tree merkletree.MerkleTree `json:"tree"`
}

func getTreeStatus(tree merkletree.ExternalMerkleTree) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tree.Length() == 0 {
			render.JSON(w, r, treeStatusResponse{MerkleAPIResponse{true, ""}, nil})
			return
		}
		render.JSON(w, r, treeStatusResponse{MerkleAPIResponse{true, ""}, tree})
		return
	}
}

type intermediaryHashesResponse struct {
	MerkleAPIResponse
	Hashes []string `json:"hashes"`
}

func getIntermediaryHashesHandler(tree merkletree.ExternalMerkleTree) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		index, err := strconv.Atoi(chi.URLParam(r, "index"))
		if err != nil {
			render.JSON(w, r, intermediaryHashesResponse{MerkleAPIResponse{false, err.Error()}, nil})
			return
		}
		hashes, err := tree.IntermediaryHashesByIndex(index)
		if err != nil {
			render.JSON(w, r, intermediaryHashesResponse{MerkleAPIResponse{false, err.Error()}, nil})
			return
		}
		render.JSON(w, r, intermediaryHashesResponse{MerkleAPIResponse{true, ""}, hashes})
	}
}

type addDataRequest struct {
	Data string `json:"data"`
}

type addDataResponse struct {
	MerkleAPIResponse
	Index int    `json:"index"`
	Hash  string `json:"hash,omitempty"`
}

func addDataHandler(tree merkletree.ExternalMerkleTree) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var b addDataRequest
		err := decoder.Decode(&b)
		if err != nil {
			render.JSON(w, r, addDataResponse{MerkleAPIResponse{false, err.Error()}, -1, ""})
			return
		}

		if b.Data == "" {
			render.JSON(w, r, addDataResponse{MerkleAPIResponse{false, "Missing data field"}, -1, ""})
			return
		}
		index, hash := tree.Add([]byte(b.Data))
		render.JSON(w, r, addDataResponse{MerkleAPIResponse{true, ""}, index, hash})
	}
}

// GetHashByLeafIndex gets hash at index 'X'
func GetHashByLeafIndex(router chi.Router, tree *postgre.PostgresMerkleTree) chi.Router {

	router.Get("/hash/{index}", getHashByLeafIndex(tree))

	return router
}

func getHashByLeafIndex(tree *postgre.PostgresMerkleTree) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		type hashResponse struct {
			Index int    `json:"index"`
			Hash  string `json:"hash"`
		}

		indexAsStr := chi.URLParam(req, "index")
		index, err := strconv.Atoi(indexAsStr)
		if err != nil {
			log.Printf("[ERROR] Invalid query param. Index should be an integer. %s", err)
			http.Error(w, "Invalid query param. Index should be an integer.", 400)
			return
		}

		hashAtIndex, err := tree.HashAt(index)
		if err != nil {
			log.Printf("[ERROR] get hash at index. %s", err)
			http.Error(w, "Invalid index.", 400)
			return
		}

		render.JSON(w, req, hashResponse{Index: index, Hash: hashAtIndex})
	}
}

// GetInfoByEthAddress gets additional info like hash, index, number of tokens by eth address
func GetInfoByEthAddress(router chi.Router, tree *postgre.PostgresMerkleTree) chi.Router {

	router.Get("/info/{ethAddress}", getInfoByEthAddress(tree))

	return router
}

func getInfoByEthAddress(tree *postgre.PostgresMerkleTree) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		type hashResponse struct {
			Index  int    `json:"index"`
			Hash   string `json:"hash"`
			Tokens string `json:"tokens"`
		}

		ethAddress := chi.URLParam(req, "ethAddress")
		if ethAddress == "" {
			http.Error(w, "Invalid request! Missing eth address!", 400)
			return
		}

		hash, index, tokens, _ := tree.GetByEthAddress(strings.ToLower(ethAddress))

		render.JSON(w, req, hashResponse{Index: index, Hash: hash, Tokens: tokens})
	}
}

// Migrate AE tokens (erc20) from ethereum network to AEs in aeternity network, validate provided sender's signature
func Migrate(router chi.Router, tree *postgre.PostgresMerkleTree, secretKey string, contractSource string, aeContractAddress string, aeNodeUrl string) chi.Router {

	router.Post("/migrate", migrate(tree, secretKey, contractSource, aeContractAddress, aeNodeUrl))

	return router
}

func migrate(tree *postgre.PostgresMerkleTree, secretKey string, contractSource string, aeContractAddress string, aeNodeUrl string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		if contractSource == "" {
			contractSource =
				`contract TokenMigration =
	type state = ()

	entrypoint migrate(amountOfTokens: string, aeAddress: string, sig: string, h: string, leafIndex: string, siblings: string) =
		require(verify(h, sig), "Invalid signature!")
		transfer(aeAddress, amountOfTokens)
		()

	function verify(h: string, sig: string) : bool = true
	function transfer(to: string, amount: string) = ()`
		}

		type reqData struct {
			EthPubKey     string `json:"ethPubKey"`
			MessageDigest string `json:"messageDigest"`
			Signature     string `json:"signature"`
			AeAddress     string `json:"aeAddress"`
		}

		decoder := json.NewDecoder(req.Body)
		var data reqData
		err := decoder.Decode(&data)
		if err != nil {
			fmt.Printf("[ERROR] Cannot parse request body! %s\n", err)
			http.Error(w, "Cannot parse request body!", 400)
			return
		}

		if data.EthPubKey == "" {
			log.Printf("[ERROR] Missing EthPubKey! Migrate procedure should NOT start!\n")
			http.Error(w, "Missing EthPubKey! Migrate procedure should NOT start!", 400)
			return
		}

		if data.MessageDigest == "" {
			log.Printf("[ERROR] Missing MessageDigest! Migrate procedure should NOT start!\n")
			http.Error(w, "Missing MessageDigest! Migrate procedure should NOT start!", 400)
			return
		}

		if data.Signature == "" {
			log.Printf("[ERROR] Missing Signature! Migrate procedure should NOT start!\n")
			http.Error(w, "Missing Signature! Migrate procedure should NOT start!", 400)
			return
		}

		if data.AeAddress == "" {
			log.Printf("[ERROR] Missing AE address! Migrate procedure should NOT start!\n")
			http.Error(w, "Missing AE address! Migrate procedure should NOT start!", 400)
			return
		}

		// get additional data from db
		hash, leafIndex, amountOfTokens, _ := tree.GetByEthAddress(data.EthPubKey)

		siblings, err := tree.IntermediaryHashesByIndex(leafIndex)
		if err != nil {
			log.Printf("[ERROR] IntermediaryHashesByIndex! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		siblingsAsStr := strings.Join(siblings, ",")

		account, err := aeternity.AccountFromHexString(secretKey)
		if err != nil {
			log.Printf("[ERROR] Account error! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		node := aeternity.NewNode(aeNodeUrl, false)
		compiler := aeternity.NewCompiler(aeternity.Config.Client.Contracts.CompilerURL, false)

		// fmt.Printf("amount type: %t\t%v\n", amountOfTokens, amountOfTokens)
		// fmt.Printf("ae addr type: %t\t%v\n", data.AeAddress, data.AeAddress)
		// fmt.Printf("signature type: %t\t%v\n", data.Signature, data.Signature)
		// fmt.Printf("hash type: %t\t%v\n", hash, hash)
		// fmt.Printf("leaf inx type: %t\t%v\n", strconv.Itoa(leafIndex), strconv.Itoa(leafIndex))
		// fmt.Printf("siblings type: %t\t%v\n", siblingsAsStr, siblingsAsStr)

		callData, err := compiler.EncodeCalldata(contractSource, "migrate", []string{fmt.Sprintf(`"\"%s\""`, amountOfTokens), fmt.Sprintf(`"\"%s\""`, data.AeAddress), fmt.Sprintf(`"\"%s\""`, data.Signature), fmt.Sprintf(`"\"%s\""`, hash), fmt.Sprintf(`"\"%s\""`, strconv.Itoa(leafIndex)), fmt.Sprintf(`"\"%s\""`, siblingsAsStr)})
		if err != nil {
			log.Printf("[ERROR] EncodeCalldata! %s\n", err)
			http.Error(w, fmt.Sprintf("Cannot encode call data. %s.", http.StatusText(500)), 500)
			return
		}

		context := aeternity.NewContextFromURL(aeNodeUrl, account.Address, false)

		var abiVersion uint16 = 1                      // aeternity.Config.Client.Contracts.ABIVersion
		var amount *big.Int = big.NewInt(1)            // aeternity.Config.Client.Contracts.Amount
		var gasPrice *big.Int = big.NewInt(1000000000) // aeternity.Config.Client.Contracts.GasPrice
		var gas *big.Int = utils.NewIntFromUint64(1e5) // aeternity.Config.Client.Contracts.Gas
		var fee *big.Int = utils.NewIntFromUint64(665480000000000)

		tx, err := context.ContractCallTx(aeContractAddress, callData, abiVersion, *amount, *gas, *gasPrice, *fee)
		if err != nil {
			log.Printf("[ERROR] ContractCallTx! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		signedTx, hash, _, err := aeternity.SignHashTx(account, &tx, "ae_devnet") // signedTx, hash, signature, err
		if err != nil {
			log.Printf("[ERROR] SignHashTx! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		// transform the tx into a tx_base64encodedstring so you can HTTP POST it
		signedTxStr, err := aeternity.SerializeTx(&signedTx)
		if err != nil {
			log.Printf("[ERROR] SerializeTx! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		err = aeternity.BroadcastTransaction(node, signedTxStr)
		if err != nil {
			log.Printf("[ERROR] BroadcastTransaction! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		height, microblock, err := waitForTransaction(node, hash)
		if err != nil {
			log.Printf("[ERROR] waitForTransaction! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		type response struct {
			Success    bool
			Height     uint64
			Microblock string
		}

		render.JSON(w, req, response{Success: true, Height: height, Microblock: microblock})
	}
}

func waitForTransaction(aeNode *aeternity.Node, hash string) (height uint64, microblockHash string, err error) {
	height = getHeight(aeNode)
	height, microblockHash, err = aeternity.WaitForTransactionUntilHeight(aeNode, hash, height+1000) // aeternity.WaitForTransactionUntilHeight(aeNode, hash, height + 1000)
	if err != nil {
		// Sometimes, the tests want the tx to fail. Return the err to let them know.
		log.Println(err)
		return 0, "", err
	}

	log.Println("=-=-=-=> Transaction was found at", height, "microblockHash", microblockHash, "err", err)
	return height, microblockHash, err
}

func getHeight(aeNode *aeternity.Node) (h uint64) {
	h, err := aeNode.GetHeight()
	if err != nil {
		log.Println("Could not retrieve chain height")
		return
	}

	return
}
