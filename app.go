package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"strings"
	"os"
	"strconv"
	"github.com/go-chi/render"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
	rlp "github.com/randomshinichi/rlpae"

	// "github.com/ethereum/go-ethereum/crypto"
	// "github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/aeternity/aepp-sdk-go/aeternity"
	"github.com/aeternity/aepp-sdk-go/utils"

	memory "aepp-token-migration-backend/memory_merkle_tree"
	db "aepp-token-migration-backend/postgre_sql"
	baseapi "aepp-token-migration-backend/rest_api/base"
	"aepp-token-migration-backend/rest_api/validator"
)

func main() {
	connectionString, port, secretKey, contractRawUrl, aeContractAddress := loadEnv()
	nodeURL := "http://localhost:3001"

	fmt.Println(secretKey)

	contractSource := getContractSource(contractRawUrl)

	fmt.Println(port)
	fmt.Println(aeContractAddress)
	fmt.Println(contractSource)

	tree := db.LoadMerkleTree(memory.NewMerkleTree(), connectionString)

	fmt.Println(tree)
	fmt.Printf("root hash: %s\n", tree.Root())

	router := chi.NewRouter()

	cors := cors.New(cors.Options{
		// AllowedOrigins: []string{"https://foo.com"}, // Use this to allow specific origin hosts
		AllowedOrigins: []string{"*"},
		// AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	})
	router.Use(cors.Handler)

	baseapi.MerkleTreeStatus(router, tree.FullMerkleTree)
	baseapi.MerkleTreeHashes(router, tree.FullMerkleTree)
	validator.MerkleTreeValidate(router, tree.FullMerkleTree)

	// add token owner to DB with given params: eht address, token amount, ae address,
	router.Post("/owner/add", func(w http.ResponseWriter, req *http.Request) {

		type requestData struct {
			EthAddress string `json:"ethAddress"`
			Balance    string `json:"balance"`
			AeAddress  string `json:"aeAddress"`
		}

		decoder := json.NewDecoder(req.Body)
		var reqData requestData
		err := decoder.Decode(&reqData)
		if err != nil {
			render.JSON(w, req, "Cannot parse request body!")
			return
		}

		if reqData.EthAddress == "" {
			render.JSON(w, req, "Missing ethAddress field!")
			return
		}

		if reqData.Balance == "" {
			render.JSON(w, req, "Invalid balance field!")
			return
		}

		data := fmt.Sprintf("%s%s", reqData.EthAddress, reqData.Balance)
		index, hash := tree.Add([]byte(data), strings.ToLower(reqData.EthAddress), reqData.Balance, reqData.AeAddress)

		fmt.Printf("index: %d, hash: %s\n", index, hash)
		fmt.Printf("root hash: %s\n", tree.Root())

		render.JSON(w, req, fmt.Sprintf("Data was successfully added! index: %d, hash: %s", index, hash))
	})

	// gets hash at index 'X' and siblings
	router.Get("/hash/{index}", func(w http.ResponseWriter, req *http.Request) {
		type hashResponse struct {
			Index int    `json:"index"`
			Hash  string `json:"hash"`
			// Siblings []string `json:"siblings"`
		}

		indexAsStr := chi.URLParam(req, "index")
		// indexAsStr := req.URL.Query().Get("index")
		index, err := strconv.Atoi(indexAsStr)
		if err != nil {
			render.JSON(w, req, "Invalid data input. Index should be an integer.")
			fmt.Printf("[ERROR] %s", err)
			return
		}

		hashAtIndex, err := tree.HashAt(index)
		if err != nil {
			render.JSON(w, req, "Invalid data input. Index should be an integer.")
			fmt.Printf("[ERROR] %s", err)
			return
		}

		render.JSON(w, req, hashResponse{Index: index, Hash: hashAtIndex})
	})

	// gets info by eth address
	router.Get("/info/{ethAddress}", func(w http.ResponseWriter, req *http.Request) {
		type hashResponse struct {
			Index  int    `json:"index"`
			Hash   string `json:"hash"`
			Tokens string `json:"tokens"`
		}

		ethAddress := chi.URLParam(req, "ethAddress")
		if ethAddress == "" {
			http.Error(w, "Invalid request! Missing eth address!", 404)
			return
		}

		hash, index, tokens, _ := tree.GetByEthAddress(strings.ToLower(ethAddress))

		render.JSON(w, req, hashResponse{Index: index, Hash: hash, Tokens: tokens})
	})

	// router.Post("tx/receive", func(w http.ResponseWriter, req *http.Request) {

	// })

	router.Post("/migrate", func(w http.ResponseWriter, req *http.Request) {
		// public key/eth address, message digest, signature

		if contractSource == "" {
			fmt.Println("==> TYK")
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
			EthPubKey string `json:"ethPubKey"`
			// MessageDigest string `json:"messageDigest"`
			Signature string `json:"signature"`
			AeAddress string `json:"aeAddress"`
		}

		decoder := json.NewDecoder(req.Body)
		var data reqData
		err := decoder.Decode(&data)
		if err != nil {
			fmt.Printf("[ERROR] Cannot parse request body! %s\n", err)
			http.Error(w, "Cannot parse request body!", 400)
			return
		}

		// get additional data from db
		hash, leafIndex, amountOfTokens, aeAddress := tree.GetByEthAddress(data.EthPubKey)

		// TODO: should owner change its ae address ?!
		if aeAddress == "" {
			aeAddress = data.AeAddress
		}

		if aeAddress == "" {
			fmt.Printf("[ERROR] Missing AE address! Migrate procedure should NOT start!\n")
			http.Error(w, "Missing AE address! Migrate procedure should NOT start!", 400)
			return
		}

		siblings, err := tree.IntermediaryHashesByIndex(leafIndex)
		if err != nil {
			fmt.Printf("[ERROR] IntermediaryHashesByIndex! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		siblingsAsStr := strings.Join(siblings, ",")

		
		account, err := aeternity.AccountFromHexString(secretKey)
		if err != nil {
			fmt.Printf("[ERROR] Account error! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		node := aeternity.NewNode(nodeURL, false)
		compiler := aeternity.NewCompiler(aeternity.Config.Client.Contracts.CompilerURL, false)

		// fmt.Printf("amount type: %t\t%v\n", amountOfTokens, amountOfTokens)
		// fmt.Printf("ae addr type: %t\t%v\n", data.AeAddress, data.AeAddress)
		// fmt.Printf("signature type: %t\t%v\n", data.Signature, data.Signature)
		// fmt.Printf("hash type: %t\t%v\n", hash, hash)
		// fmt.Printf("leaf inx type: %t\t%v\n", strconv.Itoa(leafIndex), strconv.Itoa(leafIndex))
		// fmt.Printf("siblings type: %t\t%v\n", siblingsAsStr, siblingsAsStr)

		callData, err := compiler.EncodeCalldata(contractSource, "migrate", []string{fmt.Sprintf(`"\"%s\""`, amountOfTokens), fmt.Sprintf(`"\"%s\""`, data.AeAddress), fmt.Sprintf(`"\"%s\""`, data.Signature), fmt.Sprintf(`"\"%s\""`, hash), fmt.Sprintf(`"\"%s\""`, strconv.Itoa(leafIndex)), fmt.Sprintf(`"\"%s\""`, siblingsAsStr)})
		if err != nil {
			fmt.Printf("[ERROR] EncodeCalldata! %s\n", err)
			http.Error(w, fmt.Sprintf("Cannot encode call data. %s.", http.StatusText(500)), 500)
			return
		}

		context := aeternity.NewContextFromURL(nodeURL, account.Address, false)

		var abiVersion uint16 = 1                      // aeternity.Config.Client.Contracts.ABIVersion
		var amount *big.Int = big.NewInt(1)            // aeternity.Config.Client.Contracts.Amount
		var gasPrice *big.Int = big.NewInt(1000000000) // aeternity.Config.Client.Contracts.GasPrice
		var gas *big.Int = utils.NewIntFromUint64(1e5) // aeternity.Config.Client.Contracts.GasPrice
		var fee *big.Int = utils.NewIntFromUint64(665480000000000)

		tx, err := context.ContractCallTx(aeContractAddress, callData, abiVersion, *amount, *gas, *gasPrice, *fee)
		if err != nil {
			fmt.Printf("[ERROR] ContractCallTx! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		signedTx, hash, _, err := aeternity.SignHashTx(account, &tx, "ae_devnet") // signedTx, hash, signature, err
		if err != nil {
			fmt.Printf("[ERROR] SignHashTx! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		// transform the tx into a tx_base64encodedstring so you can HTTP POST it
		signedTxStr, err := aeternity.SerializeTx(&signedTx)
		if err != nil {
			fmt.Printf("[ERROR] SerializeTx! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		err = aeternity.BroadcastTransaction(node, signedTxStr)
		if err != nil {
			fmt.Printf("[ERROR] BroadcastTransaction! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		height, microblock, err := waitForTransaction(node, hash)
		if err != nil {
			fmt.Printf("[ERROR] waitForTransaction! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		type response struct {
			Success    bool
			Height     uint64
			Microblock string
		}

		render.JSON(w, req, response{Success: true, Height: height, Microblock: microblock})
	})

	fmt.Printf("Server start on port: %d\n", port)
	strPort := fmt.Sprintf(":%d", port)
	err := http.ListenAndServe(strPort, router)
	if err != nil {
		fmt.Printf("Server cannot start has ERROR: %s", err)
	}
}

func loadEnv() (connectrinStr string, port int, secretKey string, contractRawUrl string, aeContractAddress string) {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	connectionString := os.Getenv("CONNECTION_STRING_POSTGRESQL")
	port, err = strconv.Atoi(os.Getenv("GO_API_PORT"))
	if err != nil {
		log.Fatal("Error parsing port!")
	}

	secretKey = os.Getenv("SECRET_KEY")
	contractRawUrl = os.Getenv("CONTRACT_RAW_URL_GIT")
	aeContractAddress = os.Getenv("AE_CONTRACT_TOKEN_MIGRATION_ADDRESS")

	return connectionString, port, secretKey, contractRawUrl, aeContractAddress
}

func signBroadcast(tx rlp.Encoder, acc *aeternity.Account, aeNode *aeternity.Node) (hash string) {
	signedTx, hash, _, err := aeternity.SignHashTx(acc, tx, aeternity.Config.Node.NetworkID)
	if err != nil {
		fmt.Printf("[ERROR] SignHashTx! %s\n", err)
		return
	}

	signedTxStr, err := aeternity.SerializeTx(&signedTx)
	if err != nil {
		fmt.Printf("[ERROR] Serialize! %s\n", err)
		return
	}

	fmt.Printf("=> signedTxStr: %s\n", signedTxStr)
	fmt.Printf("=> signedTx: %s\n", signedTx)
	fmt.Printf("=> hash: %s\n", hash)

	err = aeternity.BroadcastTransaction(aeNode, signedTxStr)
	if err != nil {
		fmt.Printf("[ERROR] Broadcast! %s\n", err)
		return
	}

	return hash
}

func waitForTransaction(aeNode *aeternity.Node, hash string) (height uint64, microblockHash string, err error) {
	height = getHeight(aeNode)
	height, microblockHash, err = aeternity.WaitForTransactionUntilHeight(aeNode, hash, height+1000) // aeternity.WaitForTransactionUntilHeight(aeNode, hash, height + 1000)
	if err != nil {
		// Sometimes, the tests want the tx to fail. Return the err to let them know.
		return 0, "", err
	}

	fmt.Println("=-=-=-=> Transaction was found at", height, "microblockHash", microblockHash, "err", err)
	return height, microblockHash, err
}

func getHeight(aeNode *aeternity.Node) (h uint64) {
	h, err := aeNode.GetHeight()
	if err != nil {
		fmt.Println("Could not retrieve chain height")
		return
	}
	// fmt.Println("Current Height:", h)
	return
}

func getContractSource(contractRawUrlGit string) string {
	// gitUrl := `https://raw.githubusercontent.com/aeternity/aepp-sophia-examples/master/examples/CryptoHamster/contracts/crypto-hamsters.aes`

	if contractRawUrlGit == "" {
		return ""
	}

	resp, err := http.Get(contractRawUrlGit)
	if err != nil {
		fmt.Printf("Somthing went wrong! Error: %s", err)
		return ""
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Somthing went wrong! Error: %s", err)
		return ""
	}

	return string(body)
}