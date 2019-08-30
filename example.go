package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"

	// "io/ioutil"
	// "math/big"
	// "net/http"

	types "aepp-token-migration-backend/types"
	appUtils "aepp-token-migration-backend/utils"

	// "github.com/aeternity/aepp-sdk-go/aeternity"
	"aepp-sdk-go/aeternity"

	// "github.com/aeternity/aepp-sdk-go/utils"
	"aepp-sdk-go/utils"

	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	deploy()
}

func deploy() {

	rootHash := "8CFCA1B9DDAB682EEE0CF097DADF553061A1731A325BD4A6E83FD0CA0F189F6D"

	type keyPair struct {
		PublicKey  string
		PrivateKey string
	}

	nodeURL := "http://localhost:3001"
	// zeroKp := keyPair{
	// 	PublicKey:  "ak_fUq2NesPXcYZ1CcqBcGC3StpdnQw3iVxMA3YSeCNAwfN4myQk",
	// 	PrivateKey: "7c6e602a94f30e4ea7edabe4376314f69ba7eaa2f355ecedb339df847b6f0d80575f81ffb0a297b7725dc671da0b1769b1fc5cbe45385c7b5ad1fc2eaf1d609d"}

	kp := keyPair{
		PublicKey:  "ak_2mwRmUeYmfuW93ti9HMSUJzCk1EYcQEfikVSzgo6k2VghsWhgU",
		PrivateKey: "bb9f0b01c8c9553cfbaf7ef81a50f977b1326801ebf7294d1c2cbccdedf27476e9bbf604e611b5460a3b3999e9771b6f60417d73ce7c5519e12f7e127a1225ca"}

	account, err := aeternity.AccountFromHexString(kp.PrivateKey)
	if err != nil {
		fmt.Printf("==> AccountFromHexString", err)
		return
	}

	node := aeternity.NewNode(nodeURL, false)
	// fmt.Printf("COMPILER: %s\n", aeternity.Config.Client.Contracts.CompilerURL)
	CONTRACT_SOURCE_URL_GIT_RAW := "https://raw.githubusercontent.com/LimeChain/aepp-token-migration-smart-contract/master/contracts/TokenMigration.aes" 
	contractSource := appUtils.GetContractSource(CONTRACT_SOURCE_URL_GIT_RAW)
	compiler := aeternity.NewCompiler(aeternity.Config.Client.Contracts.CompilerURL, false)
	contractByteCode, err := compiler.CompileContract(contractSource, aeternity.Config.Compiler.Backend)
	if err != nil {
		fmt.Printf("==> CompileContract %v \n", err)
		return
	}

	// acc, err := node.GetAccount(kp.PublicKey)
	// if err != nil {
	// 	fmt.Printf("[ERROR] GetAccount! %s\n", err)
	// 	return
	// }
	// nonce := acc.Nonce

	// fmt.Println(contractSource)
	// fmt.Println(contractByteCode)

	// callData, err := compiler.EncodeCalldata(contractSource, "init", []string{rootHash}) // , []string{alice.Address}
	callData, err := compiler.EncodeCalldata(contractSource, "init", []string{fmt.Sprintf("\"%s\"", rootHash)}, aeternity.Config.Compiler.Backend) // , []string{alice.Address}
	if err != nil {
		fmt.Printf("[ERROR] EncodeCalldata! %s\n", err)
		return
	}

	var abiVersion uint16 = aeternity.Config.Client.Contracts.ABIVersion // aeternity.Config.Client.Contracts.ABIVersion
	var vmVersion uint16 = aeternity.Config.Client.Contracts.VMVersion   // aeternity.Config.Client.Contracts.ABIVersion
	var amount big.Int = aeternity.Config.Client.Contracts.Amount        // big.NewInt(1)            // aeternity.Config.Client.Contracts.Amount
	var deposit big.Int = aeternity.Config.Client.Contracts.Deposit      // big.NewInt(1)           // aeternity.Config.Client.Contracts.Amount
	// var ttl uint64 = 0         // aeternity.Config.Client.Contracts.Amount
	var gasPrice *big.Int = big.NewInt(1000000000) // aeternity.Config.Client.Contracts.GasPrice
	var gas *big.Int = utils.NewIntFromUint64(1e5) // aeternity.Config.Client.Contracts.Gas
	var fee *big.Int = utils.NewIntFromUint64(665480000000000)

	// contractCreateTx := aeternity.NewContractCreateTx(kp.PublicKey, *nonce, contractByteCode, vmVersion, abiVersion, deposit, amount, *gas, *gasPrice, *fee, ttl, callData)

	context := aeternity.NewContextFromURL(nodeURL, account.Address, false)
	contractCreateTx, err := context.ContractCreateTx(contractByteCode, callData, vmVersion, abiVersion, deposit, amount, *gas, *gasPrice, *fee)
	if err != nil {
		fmt.Printf("[ERROR] ContractCreateTx! %s\n", err)
		return
	}
	// tx, err := context.ContractCallTx(aeContractAddress, callData, abiVersion, *amount, *gas, *gasPrice, *fee)

	signedTx, hash, _, err := aeternity.SignHashTx(account, &contractCreateTx, "ae_devnet") // signedTx, hash, signature, err
	if err != nil {
		fmt.Printf("[ERROR] SignHashTx! %s\n", err)
		return
	}

	fmt.Println("SignHashTx tx hash")
	fmt.Println(hash)
	fmt.Println()
	fmt.Println("contractCreateTx")
	fmt.Printf("%v\n", contractCreateTx)
	fmt.Println()

	signedTxStr, err := aeternity.SerializeTx(&signedTx)
	if err != nil {
		fmt.Printf("[ERROR] SerializeTx! %s\n\n", err)
		return
	}

	err = aeternity.BroadcastTransaction(node, signedTxStr)
	if err != nil {
		fmt.Printf("[ERROR] BroadcastTransaction! %s\n\n", err)
		return
	}

	waitForTransaction(node, hash)
	txInfo, err := node.GetTransactionByHash(hash)
	if err != nil {
		fmt.Printf("[ERROR] GetTransactionByHash! %s\n\n", err)
		return
	}

	b, err := txInfo.MarshalJSON()
	if err != nil {
		fmt.Printf("[ERROR] txInfo.MarshalJSON()! %s\n\n", err)
		return
	}

	fmt.Println()
	fmt.Printf("==> txInfo: %v \n", string(b))
}

func getTxInfo(txHash string) *types.ContractTxInfo {

	resp, err := http.Get(fmt.Sprintf("http://localhost:3001/v2/transactions/%s/info", txHash))
	if err != nil {
		log.Fatalf("[ERROR] txInfo.MarshalJSON()! %s\n", err)
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var data types.ContractTxInfo
	err = decoder.Decode(&data)
	if err != nil {
		log.Fatalf("[ERROR] json.NewDecoder(resp.Body)! %s\n", err)
	}

	fmt.Println(data)

	return &data
}

func waitForTransaction(aeNode *aeternity.Node, hash string) { // (height uint64, microblockHash string, err error)
	height := getHeight(aeNode)
	height, microblockHash, err := aeternity.WaitForTransactionForXBlocks(aeNode, hash, height+100)
	if err != nil {
		// Sometimes, the tests want the tx to fail. Return the err to let them know.
		fmt.Println("Wait for transaction", err)
		return
	}

	// fmt.Println("[INFO] Transaction was found at", height, "microblockHash", microblockHash, "err", err)
	fmt.Println("[INFO] Transaction was found at", height, "microblockHash", microblockHash)
}

func getHeight(aeNode *aeternity.Node) (h uint64) {
	h, err := aeNode.GetHeight()
	if err != nil {
		fmt.Println("Could not retrieve chain height")
		return
	}

	return
}

func testKeccak() {

	ethAddrLeft := "0xdD13a2E199121E53A32BECB588b8c9b4dAd6BA0E"
	tokensLeft := "80856967965736379088896"
	dataLeft := appUtils.PreHashFormat(ethAddrLeft, tokensLeft)
	left := strings.ToUpper(crypto.Keccak256Hash([]byte(dataLeft)).Hex()[2:])

	fmt.Println("left hash: ", left)

	ethAddrRight := "0x19Ae739E15ab9C68AA136c4e841C4762693e5811"
	tokensRight := "337858228211646684200960"
	dataRight := appUtils.PreHashFormat(ethAddrRight, tokensRight)
	right := strings.ToUpper(crypto.Keccak256Hash([]byte(dataRight)).Hex()[2:])

	fmt.Println("right hash: ", right)

	left = "7941FE89909B7A465D1B6626932AB309B41D4DF3A20C16319FDFCF6FC886FF9D"
	right = "118AFD786E4E19451CC92C5313D46EB0DB928E023D9D2080D896BA32490EF87B"

	// hash := fmt.Sprintf("%s%s", ethAddr, tokens)

	h := crypto.Keccak256Hash([]byte(left), []byte(right))

	// hh := crypto.Keccak256Hash([]byte(strings.ToUpper(ethAddr)), []byte(strings.ToUpper(tokens)))
	// hhh := crypto.Keccak256Hash([]byte("0x603339837faa719f6313adacd7863f455211fb8e6b3f7054c000d80fb3ae7f9e"), []byte("0x603339837faa719f6313adacd7863f455211fb8e6b3f7054c000d80fb3ae7f9e"))
	// a := strings.ToUpper("603339837faa719f6313adacd7863f455211fb8e6b3f7054c000d80fb3ae7f9e")
	// hhhh := crypto.Keccak256Hash([]byte(a), []byte(a))

	fmt.Println("h", strings.ToUpper(h.Hex()[2:]))
	// fmt.Println("lower", h.Hex())
	// fmt.Println("upper", hh.Hex())
	// fmt.Println("hhh", hhh.Hex())
	// fmt.Println("hhhh", hhhh.Hex())

}

// func main() {

// 	contractAddress := "ct_2Ker9cb12skKWR2UZLxuT63MZRStC34KkUA9QMAiQFN6DNe5vC"
// 	nodeURL := "http://localhost:3001"

// 	type keyPair struct {
// 		PublicKey  string
// 		PrivateKey string
// 	}

// 	key := keyPair{
// 		PublicKey:  "ak_fUq2NesPXcYZ1CcqBcGC3StpdnQw3iVxMA3YSeCNAwfN4myQk",
// 		PrivateKey: "7c6e602a94f30e4ea7edabe4376314f69ba7eaa2f355ecedb339df847b6f0d80575f81ffb0a297b7725dc671da0b1769b1fc5cbe45385c7b5ad1fc2eaf1d609d"}

// 	account, err := aeternity.AccountFromHexString(key.PrivateKey)
// 	if err != nil {
// 		fmt.Printf("==> AccountFromHexString", err)
// 		return
// 	}

// 	node := aeternity.NewNode(nodeURL, false)
// 	// fmt.Printf("COMPILER: %s\n", aeternity.Config.Client.Contracts.CompilerURL)
// 	compiler := aeternity.NewCompiler(aeternity.Config.Client.Contracts.CompilerURL, false)

// 	contractSource := `contract TokenMigration =
// 		type state = ()

// 		entrypoint migrate() = ()
// 		// entrypoint verify(x: string) : bool = true`

// 	callData, err := compiler.EncodeCalldata(contractSource, "migrate", []string{}) // , []string{alice.Address}
// 	if err != nil {
// 		fmt.Printf("[ERROR] EncodeCalldata! %s\n", err)
// 		return
// 	}

// 	// helpers := aeternity.Helpers{Node: node}
// 	// contract := aeternity.Context{Helpers: helpers, Address: key.PublicKey}

// 	ctx := aeternity.NewContextFromURL(nodeURL, key.PublicKey, true)

// 	var abiVersion uint16 = 1                      // aeternity.Config.Client.Contracts.ABIVersion
// 	var amount *big.Int = big.NewInt(1)            // aeternity.Config.Client.Contracts.Amount
// 	var gasPrice *big.Int = big.NewInt(1000000000) // aeternity.Config.Client.Contracts.GasPrice
// 	var gas *big.Int = utils.NewIntFromUint64(1e5) // aeternity.Config.Client.Contracts.GasPrice
// 	var fee *big.Int = utils.NewIntFromUint64(665480000000000)

// 	tx, err := ctx.ContractCallTx(contractAddress, callData, abiVersion, *amount, *gas, *gasPrice, *fee)
// 	if err != nil {
// 		fmt.Printf("[ERROR] ContractCallTx! %s\n", err)
// 		return
// 	}

// 	fmt.Println(tx)

// 	height, _ := node.GetHeight()

// 	fmt.Println("        ")
// 	fmt.Printf("==> height: %v \n", height)
// 	fmt.Printf("==> contractAddress: %s \n", contractAddress)
// 	fmt.Printf("==> callData: %s \n", callData)
// 	fmt.Printf("==> amount: %s \n", amount)
// 	fmt.Printf("==> ABIVersion: %d \n", abiVersion)
// 	fmt.Printf("==> gas: %s \n", gas)
// 	fmt.Printf("==> gas price: %s \n", gasPrice)
// 	fmt.Printf("==> fee: %s \n", fee)
// 	fmt.Println("        ")

// 	// fmt.Printf("NetworkID: %s\n", aeternity.Config.Node.NetworkID)

// 	// aa := "tx_+L0rAaEB6bv2BOYRtUYKOzmZ6Xcbb2BBfXPOfFUZ4S9+EnoSJcoNoQWuDIlrtX5o+od+RMM0lnwJM6ujrUvUGQ90ZiDvr3hq+QGHAZy/M+RYAAABgxgX+IQ7msoAuGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIBTESDFrJ3ThKpSQmPm0ASyca+RQ3Yxp992RkV9H/QImAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADUmg+0"

// 	// newTx, err := aeternity.DeserializeTxStr(aa)
// 	// if err != nil {
// 	// 	fmt.Printf("[ERROR] DeserializeTxStr! %s\n\n", err)
// 	// 	return
// 	// }

// 	// signedTx, hash, signature, err := aeternity.SignHashTx(account, newTx, "ae_devnet")
// 	signedTx, hash, signature, err := aeternity.SignHashTx(account, &tx, "ae_devnet")
// 	if err != nil {
// 		fmt.Printf("[ERROR] SignHashTx! %s\n", err)
// 		return
// 	}

// 	fmt.Printf("signedTx %s\n", signedTx)
// 	fmt.Printf("hash %s\n", hash)
// 	fmt.Printf("signature %s\n\n", signature)

// 	// transform the tx into a tx_base64encodedstring so you can HTTP POST it
// 	signedTxStr, err := aeternity.SerializeTx(&signedTx)
// 	if err != nil {
// 		fmt.Printf("[ERROR] SerializeTx! %s\n\n", err)
// 		return
// 	}

// 	// hardcoded signed tx from another wallet
// 	// signedTxStr = "tx_+QEHCwH4QrhAysY5FATHgVEh8VGvuAbQhtULcpLxDGfnzJUb65wF57c/IaSqVUKO/tLH1MkBB7oTGttFfqxPNRiQZu/a+7eOCri/+L0rAaEB7rRLxYtB2ulh6urhPK3dTHn70dT+PQVEo+/UlL+Kx4wBoQWuDIlrtX5o+od+RMM0lnwJM6ujrUvUGQ90ZiDvr3hq+QGHAZy/M+RYAAABgxgX+IQ7msoAuGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIBTESDFrJ3ThKpSQmPm0ASyca+RQ3Yxp992RkV9H/QImAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAh6iyR"

// 	fmt.Println(" ==> signedTxStr <<--")
// 	fmt.Println(signedTxStr)

// 	err = aeternity.BroadcastTransaction(node, signedTxStr)
// 	if err != nil {
// 		fmt.Printf("[ERROR] BroadcastTransaction 1! %s\n\n", err)
// 		return
// 	}

// 	fmt.Println(">> SUCCESS <<")
// }
