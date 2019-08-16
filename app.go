package main

import (
	"github.com/go-chi/render"
	"fmt"
	"log"
	"os"
	"strconv"
	"encoding/json"

	"net/http"
	"github.com/go-chi/chi"

	"github.com/joho/godotenv"
	db "aepp-token-migration-backend/postgre_sql"
	memory "aepp-token-migration-backend/memory_merkle_tree"
	"aepp-token-migration-backend/rest_api/validator"
	"aepp-token-migration-backend/rest_api/base"

	// "github.com/ethereum/go-ethereum/crypto"
	// "github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/aeternity/aepp-sdk-go/aeternity"
	"github.com/aeternity/aepp-sdk-go/utils"
	// "math/big"

	rlp "github.com/randomshinichi/rlpae"
)

func main() {
	connectionString, port := loadEnv()

	fmt.Println(port)
	
	tree := db.LoadMerkleTree(memory.NewMerkleTree(), connectionString)

	fmt.Println(tree)
	fmt.Printf("root hash: %s\n", tree.Root())

	router := chi.NewRouter()

	baseapi.MerkleTreeStatus(router, tree.FullMerkleTree)
	baseapi.MerkleTreeHashes(router, tree.FullMerkleTree)
	validator.MerkleTreeValidate(router, tree.FullMerkleTree)

	
	router.Post("/owner/add", func(w http.ResponseWriter, req *http.Request) {

		type requestData struct {
			EthAddress string `json:"ethAddress"`
			Balance string `json:"balance"`
			AeAddress string `json:"aeAddress"`
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
		index, hash := tree.Add([]byte(data), reqData.EthAddress, reqData.Balance, reqData.AeAddress)

		fmt.Printf("index: %d, hash: %s\n", index, hash)
		fmt.Printf("root hash: %s\n", tree.Root())

		render.JSON(w, req, fmt.Sprintf("Data was successfully added! index: %d, hash: %s", index, hash))
	})


	// gets hash at index 'X' and siblings
	router.Get("/hash/{index}", func(w http.ResponseWriter, req *http.Request) {
		type hashResponse struct {
			Index int `json:"index"`
			Hash string `json:"hash"`
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

	

	// router.Post("tx/receive", func(w http.ResponseWriter, req *http.Request) {
	// 	
	// })

	// router.Post("tx/sign", func(w http.ResponseWriter, req *http.Request) {
	// 	
	// })

	// router.Post("tx/raw", func(w http.ResponseWriter, req *http.Request) {
	// 	
	// })

	router.Post("/migrate", func(w http.ResponseWriter, req *http.Request) {
			// public key/eth address, message digest, signature

			type reqData struct {
				Address string `json:"address"`
				PubKey string `json:"pubKey"`
				MessageDigest string `json:"messageDigest"`
				Sig string `json:"sig"`
				UnsignedTx string `json:"unsignedTx"`
			}

			decoder := json.NewDecoder(req.Body)
			var data reqData
			err := decoder.Decode(&data)
			if err != nil {
				render.JSON(w, req, fmt.Sprintf("Cannot parse request body! %s\n", err))
				return
			}

			contractAddress := "ct_2kWCEEgo35ic93wAfpeaugVKeYYyaupCUQHs3u6YUDHLQPRcUd"
			nodeURL := "http://localhost:3001"
			fmt.Println(contractAddress)

			type keyPair struct {
				PublicKey string
				PrivateKey string
			}

			key := keyPair{ 
				PublicKey: "ak_2mwRmUeYmfuW93ti9HMSUJzCk1EYcQEfikVSzgo6k2VghsWhgU",
				PrivateKey: "bb9f0b01c8c9553cfbaf7ef81a50f977b1326801ebf7294d1c2cbccdedf27476e9bbf604e611b5460a3b3999e9771b6f60417d73ce7c5519e12f7e127a1225ca" }

			account, err := aeternity.AccountFromHexString(key.PrivateKey)
			if err != nil {
				fmt.Println("==> account err")
				fmt.Println(err)
				return
			}

			node := aeternity.NewNode(nodeURL, true)
			ac, _ := node.GetAccount(key.PublicKey)
			nonce := ac.Nonce


			ctx := aeternity.NewContextFromURL(nodeURL, key.PublicKey, false)

			rawTx := data.UnsignedTx

			//phase 1 gen callTx
			// helpers := aeternity.Helpers{Node: node}
			// contractsAlice := aeternity.Context{Helpers: helpers, Address: key.PublicKey}
			
			// start phase 1
			// callTx, err := contractsAlice.ContractCallTx(contractAddress, rawTx, aeternity.Config.Client.Contracts.ABIVersion, aeternity.Config.Client.Contracts.Amount, *utils.NewIntFromUint64(1e5), aeternity.Config.Client.Contracts.GasPrice, *utils.NewIntFromUint64(665480000000000))
			// if err != nil {
			// 	fmt.Printf("[ERROR] ContractCallTx! %s\n", err)
			// 	return
			// }

			// fmt.Printf("Call %+v\n", callTx)
			// end phase 1
			
				
			// convert unsigned tx to Transaction obj/struct
			myTx, err := aeternity.DeserializeTxStr(rawTx)
			if err != nil {
				fmt.Printf("[ERROR] DeserializeTxStr! %s\n\n", err)
				return
			}


			// phase 2
			txHash := signBroadcast(myTx, account, node)
			
			//phase 3
			_, _, err = waitForTransaction(node, txHash)
			if err != nil {
				fmt.Printf("[ERROR] waitForTransaction! %s\n", err)
				return
			}

			fmt.Printf("==> waitForTransaction:\n", txHash)

			fmt.Println("account")
			fmt.Println(account)

			fmt.Println("node")
			fmt.Println(node)

			fmt.Println(nonce)
			fmt.Println(ctx)

			render.JSON(w, req, "ok")
	})

	fmt.Printf("Server start on port: %d\n", port)
	strPort := fmt.Sprintf(":%d", port)
	err := http.ListenAndServe(strPort, router)
	if err != nil {
		fmt.Printf("Server cannot start has ERROR: %s", err)
	}
}

func loadEnv() (string, int){
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	connectionString := os.Getenv("CONNECTION_STRING_POSTGRESQL")
	port, err := strconv.Atoi(os.Getenv("GO_API_PORT"))
	if err != nil {
		log.Fatal("Error parsing port!")
	}

	return connectionString, port
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
	// fmt.Println("Waiting for", hash)
	fmt.Println("==> height", height)
	height, microblockHash, err = aeternity.WaitForTransactionUntilHeight(aeNode, hash, height-1000)
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