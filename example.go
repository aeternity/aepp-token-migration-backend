package main

import (
	"fmt"
	"math/big"

	"github.com/aeternity/aepp-sdk-go/aeternity"
	"github.com/aeternity/aepp-sdk-go/utils"
)

func main() {
	contractAddress := "ct_2Ker9cb12skKWR2UZLxuT63MZRStC34KkUA9QMAiQFN6DNe5vC"
	nodeURL := "http://localhost:3001"

	type keyPair struct {
		PublicKey  string
		PrivateKey string
	}

	key := keyPair{
		PublicKey:  "ak_fUq2NesPXcYZ1CcqBcGC3StpdnQw3iVxMA3YSeCNAwfN4myQk",
		PrivateKey: "7c6e602a94f30e4ea7edabe4376314f69ba7eaa2f355ecedb339df847b6f0d80575f81ffb0a297b7725dc671da0b1769b1fc5cbe45385c7b5ad1fc2eaf1d609d"}

	account, err := aeternity.AccountFromHexString(key.PrivateKey)
	if err != nil {
		fmt.Printf("==> AccountFromHexString", err)
		return
	}

	node := aeternity.NewNode(nodeURL, false)
	// fmt.Printf("COMPILER: %s\n", aeternity.Config.Client.Contracts.CompilerURL)
	compiler := aeternity.NewCompiler(aeternity.Config.Client.Contracts.CompilerURL, false)

	contractSource := `contract TokenMigration =
		type state = ()
		
		entrypoint migrate() = ()
		// entrypoint verify(x: string) : bool = true`

	callData, err := compiler.EncodeCalldata(contractSource, "migrate", []string{}) // , []string{alice.Address}
	if err != nil {
		fmt.Printf("[ERROR] EncodeCalldata! %s\n", err)
		return
	}

	// helpers := aeternity.Helpers{Node: node}
	// contract := aeternity.Context{Helpers: helpers, Address: key.PublicKey}

	ctx := aeternity.NewContextFromURL(nodeURL, key.PublicKey, true)

	var abiVersion uint16 = 1 // aeternity.Config.Client.Contracts.ABIVersion
	var amount *big.Int = big.NewInt(1)   // aeternity.Config.Client.Contracts.Amount
	var gasPrice *big.Int = big.NewInt(1000000000) // aeternity.Config.Client.Contracts.GasPrice
	var gas *big.Int = utils.NewIntFromUint64(1e5) // aeternity.Config.Client.Contracts.GasPrice
	var fee *big.Int = utils.NewIntFromUint64(665480000000000)

	tx, err := ctx.ContractCallTx(contractAddress, callData, abiVersion, *amount, *gas, *gasPrice, *fee)
	if err != nil {
		fmt.Printf("[ERROR] ContractCallTx! %s\n", err)
		return
	}

	fmt.Println(tx)

	height, _ := node.GetHeight()
	
	fmt.Println("        ")
	fmt.Printf("==> height: %v \n", height)
	fmt.Printf("==> contractAddress: %s \n", contractAddress)
	fmt.Printf("==> callData: %s \n", callData)
	fmt.Printf("==> amount: %s \n", amount)
	fmt.Printf("==> ABIVersion: %d \n", abiVersion)
	fmt.Printf("==> gas: %s \n", gas)
	fmt.Printf("==> gas price: %s \n", gasPrice)
	fmt.Printf("==> fee: %s \n", fee)
	fmt.Println("        ")

	// fmt.Printf("NetworkID: %s\n", aeternity.Config.Node.NetworkID)

	// aa := "tx_+L0rAaEB6bv2BOYRtUYKOzmZ6Xcbb2BBfXPOfFUZ4S9+EnoSJcoNoQWuDIlrtX5o+od+RMM0lnwJM6ujrUvUGQ90ZiDvr3hq+QGHAZy/M+RYAAABgxgX+IQ7msoAuGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIBTESDFrJ3ThKpSQmPm0ASyca+RQ3Yxp992RkV9H/QImAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADUmg+0"

	// newTx, err := aeternity.DeserializeTxStr(aa)
	// if err != nil {
	// 	fmt.Printf("[ERROR] DeserializeTxStr! %s\n\n", err)
	// 	return
	// }

	// signedTx, hash, signature, err := aeternity.SignHashTx(account, newTx, "ae_devnet")
	signedTx, hash, signature, err := aeternity.SignHashTx(account, &tx, "ae_devnet")
	if err != nil {
		fmt.Printf("[ERROR] SignHashTx! %s\n", err)
		return
	}

	fmt.Printf("signedTx %s\n", signedTx)
	fmt.Printf("hash %s\n", hash)
	fmt.Printf("signature %s\n\n", signature)

	// transform the tx into a tx_base64encodedstring so you can HTTP POST it
	signedTxStr, err := aeternity.SerializeTx(&signedTx)
	if err != nil {
		fmt.Printf("[ERROR] SerializeTx! %s\n\n", err)
		return
	}

	err = aeternity.BroadcastTransaction(node, signedTxStr)
	if err != nil {
		fmt.Printf("[ERROR] BroadcastTransaction 1! %s\n\n", err)
		return
	}

	fmt.Println(">> SUCCESS <<")
}
