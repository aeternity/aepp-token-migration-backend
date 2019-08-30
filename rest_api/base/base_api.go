package baseapi

import (
	"aepp-sdk-go/aeternity"
	// "github.com/aeternity/aepp-sdk-go/aeternity"

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
	appUtils "aepp-token-migration-backend/utils"
	types "aepp-token-migration-backend/types"

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
// func MerkleTreeInsert(treeRouter chi.Router, tree merkletree.ExternalMerkleTree) chi.Router {
// 	treeRouter.Post("/", addDataHandler(tree))
// 	return treeRouter
// }

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

		appUtils.LogRequest(r, "get /")

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
		appUtils.LogRequest(r, "/siblings/{index}")

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

// func addDataHandler(tree merkletree.ExternalMerkleTree) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {

// 		appUtils.LogRequest(r, "post /")

// 		decoder := json.NewDecoder(r.Body)
// 		var b addDataRequest
// 		err := decoder.Decode(&b)
// 		if err != nil {
// 			render.JSON(w, r, addDataResponse{MerkleAPIResponse{false, err.Error()}, -1, ""})
// 			return
// 		}

// 		if b.Data == "" {
// 			render.JSON(w, r, addDataResponse{MerkleAPIResponse{false, "Missing data field"}, -1, ""})
// 			return
// 		}
// 		index, hash := tree.Add([]byte(b.Data))
// 		render.JSON(w, r, addDataResponse{MerkleAPIResponse{true, ""}, index, hash})
// 	}
// }

// GetHashByLeafIndex gets hash at index 'X'
func GetHashByLeafIndex(router chi.Router, tree *postgre.PostgresMerkleTree) chi.Router {

	router.Get("/hash/{index}", getHashByLeafIndex(tree))

	return router
}

func getHashByLeafIndex(tree *postgre.PostgresMerkleTree) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		appUtils.LogRequest(req, "/hash/{index}")
		
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
			Index    int    `json:"index"`
			Hash     string `json:"hash"`
			Tokens   string `json:"tokens"`
			Migrated bool   `json:"migrated"`
			MigrateTxHash string   `json:"migrateTxHash"`
		}

		ethAddress := chi.URLParam(req, "ethAddress")
		if ethAddress == "" {
			appUtils.LogRequest(req, fmt.Sprintf("/info/%s", "missing_eth_address"))
			http.Error(w, "Invalid request! Missing eth address!", 400)
			return
		}

		appUtils.LogRequest(req, fmt.Sprintf("/info/%s", ethAddress))

		// hash, index, tokens, _ := tree.GetByEthAddress(strings.ToLower(ethAddress))
		migrationInfo := tree.GetByEthAddress(strings.ToLower(ethAddress))

		render.JSON(w, req, hashResponse{Index: migrationInfo.Leaf_index, Hash: migrationInfo.Hash, Tokens: migrationInfo.Balance, Migrated: migrationInfo.Migrated == 1, MigrateTxHash: migrationInfo.Migrate_tx_hash})
	}
}

// Migrate AE tokens (erc20) from ethereum network to AEs in aeternity network, validate provided sender's signature
func Migrate(router chi.Router, tree *postgre.PostgresMerkleTree, secretKey string, contractSource string, aeContractAddress string, aeNodeUrl string) chi.Router {

	router.Post("/migrate", migrate(tree, secretKey, contractSource, aeContractAddress, aeNodeUrl))

	// TODO: DEL-ME
	router.Post("/migrate1", migrate1(tree, secretKey, contractSource, aeContractAddress, aeNodeUrl))

	return router
}

func migrate(tree *postgre.PostgresMerkleTree, secretKey string, contractSource string, aeContractAddress string, aeNodeUrl string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		appUtils.LogRequest(req, "/migrate")

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
		migrationInfo := tree.GetByEthAddress(data.EthPubKey)

		if migrationInfo.Migrated == 1 {
			log.Println("[ERROR] Eth [", data.EthPubKey, "] address already migrate its tokens!")
			http.Error(w, "Eth address already migrate its tokens!", 400)
			return
		}

		// // uncomment me

		siblings, err := tree.IntermediaryHashesByIndex(migrationInfo.Leaf_index)
		if err != nil {
			log.Printf("[ERROR] IntermediaryHashesByIndex! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		for i, j := 0, len(siblings)-1; i < j; i, j = i+1, j-1 {
			siblings[i], siblings[j] = siblings[j], siblings[i]
		}

		siblingsAsStr := "["
		for index, element := range siblings {
			// index is the index where we are
			// element is the element from someSlice for where we are
			if index == len(siblings) - 1 {
				siblingsAsStr += fmt.Sprintf("\"%v\"", element)
			} else {
				siblingsAsStr += fmt.Sprintf("\"%v\",", element)
			}
		}

		siblingsAsStr += "]"

		account, err := aeternity.AccountFromHexString(secretKey)
		if err != nil {
			log.Printf("[ERROR] Account error! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		node := aeternity.NewNode(aeNodeUrl, false)
		compiler := aeternity.NewCompiler(aeternity.Config.Client.Contracts.CompilerURL, false)
		// _, err = compiler.CompileContract(contractSource, aeternity.Config.Compiler.Backend)
		// if err != nil {
		// 	log.Printf("[ERROR] CompileContract! %s\n", err)
		// 	http.Error(w, http.StatusText(500), 500)
		// 	return
		// }

		ethAddress := strings.ToUpper(data.EthPubKey)
		signature := data.Signature[2:]

		log.Println("SIGNATURE:", signature)

		// signature := data.Signature[2:]
		// signature = signature[len(signature)-2:] + signature[2:]

		logout := true

		if logout {
			fmt.Println()
			fmt.Println("--> passed VALUES <<--")
			fmt.Println(migrationInfo.Balance) 
			fmt.Println(data.AeAddress) 
			fmt.Println(migrationInfo.Leaf_index)
			fmt.Println(siblingsAsStr)
			fmt.Println(ethAddress)
			fmt.Println()
			fmt.Println(ethAddress[2:])
			fmt.Println([]byte(ethAddress)[2:])
			fmt.Println()
			fmt.Println(signature)
			fmt.Println([]byte(signature))
			fmt.Println()
			fmt.Println(data.MessageDigest[2:])
			fmt.Println([]byte(data.MessageDigest)[2:])
			fmt.Println()
		}
		
		
		// log.Println("--- END ----")




		callData, err := compiler.EncodeCalldata(
			contractSource, 
			"migrate", 
			[]string{ fmt.Sprintf(`"\"%s\""`, migrationInfo.Balance), 
					  fmt.Sprintf(`"\"%s\""`, data.AeAddress), 
					  fmt.Sprintf(`%v`, strconv.Itoa(migrationInfo.Leaf_index)), // fmt.Sprintf(`"%s"`, strconv.Itoa(migrationInfo.Leaf_index)), // strconv.Itoa(migrationInfo.Leaf_index),
					  fmt.Sprintf(`%s`, siblingsAsStr),
					  fmt.Sprintf(`"\"%s\""`, ethAddress),
					  fmt.Sprintf(`#%s`, []byte(ethAddress)[2:]), 
					  fmt.Sprintf(`#%s`, []byte(signature)), 
					  fmt.Sprintf(`#%s`, []byte(data.MessageDigest)[2:]) },
			aeternity.Config.Compiler.Backend)
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

		// // END uncomment me

		type response struct {
			TxHash string
		}

		// hash := "0x_some_tx_hash"
		log.Println("TX hash:", hash)
		render.JSON(w, req, response{TxHash: hash})

		go waitForTransaction(tree, node, hash, data.EthPubKey, data.AeAddress)
	}
}

func getTxInfo(txHash string) *types.ContractTxInfo {

	resp, err := http.Get(fmt.Sprintf("http://localhost:3001/v2/transactions/%s/info", txHash))
	if err != nil {
		log.Panicf("[ERROR] txInfo.MarshalJSON()! %s\n", err)
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var data types.ContractTxInfo
	err = decoder.Decode(&data)
	if err != nil {
		log.Panicf("[ERROR] json.NewDecoder(resp.Body)! %s\n", err)
	}

	fmt.Println(data)

	return &data
}

func migrate1(tree *postgre.PostgresMerkleTree, secretKey string, contractSource string, aeContractAddress string, aeNodeUrl string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		appUtils.LogRequest(req, "/migrate1")

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
		migrationInfo := tree.GetByEthAddress(data.EthPubKey)

		if migrationInfo.Migrated == 1 {
			log.Println("[ERROR] Eth address already migrate its tokens!")
			http.Error(w, "Eth address already migrate its tokens!", 400)
			return
		}

		// // uncomment me

		// siblings, err := tree.IntermediaryHashesByIndex(migrationInfo.Leaf_index)
		// if err != nil {
		// 	log.Printf("[ERROR] IntermediaryHashesByIndex! %s\n", err)
		// 	http.Error(w, http.StatusText(500), 500)
		// 	return
		// }

		// for i, j := 0, len(siblings)-1; i < j; i, j = i+1, j-1 {
		// 	siblings[i], siblings[j] = siblings[j], siblings[i]
		// }

		// siblingsAsStr := strings.Join(siblings, ",")

		// account, err := aeternity.AccountFromHexString(secretKey)
		// if err != nil {
		// 	log.Printf("[ERROR] Account error! %s\n", err)
		// 	http.Error(w, http.StatusText(500), 500)
		// 	return
		// }

		// fmt.Println(1111)

		node := aeternity.NewNode(aeNodeUrl, false)
		// compiler := aeternity.NewCompiler(aeternity.Config.Client.Contracts.CompilerURL, false)

		// ethAddress := strings.ToUpper(data.EthPubKey)

		// callData, err := compiler.EncodeCalldata(
		// 	contractSource, 
		// 	"migrate", 
		// 	[]string{ migrationInfo.Balance, 
		// 			  fmt.Sprintf(`"\"%s\""`, data.AeAddress), 
		// 			  strconv.Itoa(migrationInfo.Leaf_index),
		// 			  fmt.Sprintf(`"\"%s\""`, siblingsAsStr),
		// 			  fmt.Sprintf(`"\"%s\""`, ethAddress),
		// 			  fmt.Sprintf(`"\"%s\""`, []byte(ethAddress)[2:]), 
		// 			  fmt.Sprintf(`"\"%s\""`, []byte(data.Signature)[2:]), 
		// 			  fmt.Sprintf(`"\"%s\""`, []byte(data.MessageDigest)[2:])})
		// if err != nil {
		// 	log.Printf("[ERROR] EncodeCalldata! %s\n", err)
		// 	http.Error(w, fmt.Sprintf("Cannot encode call data. %s.", http.StatusText(500)), 500)
		// 	return
		// }

		// context := aeternity.NewContextFromURL(aeNodeUrl, account.Address, false)

		// var abiVersion uint16 = 1                      // aeternity.Config.Client.Contracts.ABIVersion
		// var amount *big.Int = big.NewInt(1)            // aeternity.Config.Client.Contracts.Amount
		// var gasPrice *big.Int = big.NewInt(1000000000) // aeternity.Config.Client.Contracts.GasPrice
		// var gas *big.Int = utils.NewIntFromUint64(1e5) // aeternity.Config.Client.Contracts.Gas
		// var fee *big.Int = utils.NewIntFromUint64(665480000000000)

		// tx, err := context.ContractCallTx(aeContractAddress, callData, abiVersion, *amount, *gas, *gasPrice, *fee)
		// if err != nil {
		// 	log.Printf("[ERROR] ContractCallTx! %s\n", err)
		// 	http.Error(w, http.StatusText(500), 500)
		// 	return
		// }

		// signedTx, hash, _, err := aeternity.SignHashTx(account, &tx, "ae_devnet") // signedTx, hash, signature, err
		// if err != nil {
		// 	log.Printf("[ERROR] SignHashTx! %s\n", err)
		// 	http.Error(w, http.StatusText(500), 500)
		// 	return
		// }

		// // transform the tx into a tx_base64encodedstring so you can HTTP POST it
		// signedTxStr, err := aeternity.SerializeTx(&signedTx)
		// if err != nil {
		// 	log.Printf("[ERROR] SerializeTx! %s\n", err)
		// 	http.Error(w, http.StatusText(500), 500)
		// 	return
		// }

		// err = aeternity.BroadcastTransaction(node, signedTxStr)
		// if err != nil {
		// 	log.Printf("[ERROR] BroadcastTransaction! %s\n", err)
		// 	http.Error(w, http.StatusText(500), 500)
		// 	return
		// }

		// // END uncomment me

		type response struct {
			TxHash string
		}

		hash := "0x_some_tx_hash"
		render.JSON(w, req, response{TxHash: hash})

		go waitForTransaction1(tree, node, hash, data.EthPubKey, data.AeAddress)
	}
}

func waitForTransaction(tree *postgre.PostgresMerkleTree, aeNode *aeternity.Node, hash string, ethAddress string, aeAddress string) { // (height uint64, microblockHash string, err error)
	height := getHeight(aeNode)
	height, microblockHash, err := aeternity.WaitForTransactionForXBlocks(aeNode, hash, height + 100)
	if err != nil {
		// Sometimes, the tests want the tx to fail. Return the err to let them know.
		log.Println("Wait for transaction", err)
		return
	}

	tree.SetMigratedToSuccess(ethAddress, hash, aeAddress)
	log.Println("[INFO] Transaction was found at", height, "microblockHash", microblockHash)
	getTxInfo(hash)
}

func waitForTransaction1(tree *postgre.PostgresMerkleTree, aeNode *aeternity.Node, hash string, ethAddress string, aeAddress string) { // (height uint64, microblockHash string, err error)
	// height := getHeight(aeNode)
	// height, microblockHash, err := aeternity.WaitForTransactionForXBlocks(aeNode, hash, height + 100)
	// if err != nil {
	// 	// Sometimes, the tests want the tx to fail. Return the err to let them know.
	// 	log.Println("Wait for transaction", err)
	// 	return
	// }

	tree.SetMigratedToSuccess(ethAddress, hash, aeAddress)
	log.Println("[INFO] Transaction was found at", 666, "0xMicroblockHash", "0xMicroblockHash")
}

func getHeight(aeNode *aeternity.Node) (h uint64) {
	h, err := aeNode.GetHeight()
	if err != nil {
		log.Println("Could not retrieve chain height")
		return
	}

	return
}
