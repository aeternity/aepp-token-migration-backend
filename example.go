package main

import (
	"fmt"

	"github.com/aeternity/aepp-sdk-go/aeternity"
	"github.com/aeternity/aepp-sdk-go/utils"
)

func main() {
	contractAddress := "ct_HVb6d4kirgqzY1rShmzRTRwukcsXobjHcpLVD2EggoHmn6wt2"
	nodeURL := "http://localhost:3001"

	type keyPair struct {
		PublicKey  string
		PrivateKey string
	}

	key := keyPair{
		PublicKey:  "ak_2mwRmUeYmfuW93ti9HMSUJzCk1EYcQEfikVSzgo6k2VghsWhgU",
		PrivateKey: "bb9f0b01c8c9553cfbaf7ef81a50f977b1326801ebf7294d1c2cbccdedf27476e9bbf604e611b5460a3b3999e9771b6f60417d73ce7c5519e12f7e127a1225ca"}

	account, err := aeternity.AccountFromHexString(key.PrivateKey)
	if err != nil {
		fmt.Printf("==> AccountFromHexString", err)
		return
	}

	node := aeternity.NewNode(nodeURL, true)
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
	tx, err := ctx.ContractCallTx(contractAddress, callData, aeternity.Config.Client.Contracts.ABIVersion, aeternity.Config.Client.Contracts.Amount, *utils.NewIntFromUint64(1e5), aeternity.Config.Client.Contracts.GasPrice, *utils.NewIntFromUint64(665480000000000))
	if err != nil {
		fmt.Printf("[ERROR] ContractCallTx! %s\n", err)
		return
	}

	// fmt.Printf("NetworkID: %s\n", aeternity.Config.Node.NetworkID)
	signedTx, hash, signature, err := aeternity.SignHashTx(account, &tx, "ae_devnet")
	if err != nil {
		fmt.Printf("[ERROR] SignHashTx! %s\n", err)
		return
	}

	fmt.Printf("signedTx %s\n", signedTx)
	fmt.Printf("hash %s\n", hash)
	fmt.Printf("signature %s\n\n", signature)

	// transform the tx into a tx_base64encodedstring so you can HTTP POST it
	signedTxStr, err := aeternity.SerializeTx(&tx)
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

	// RESULT IS =>

	// 	{"reason":"Invalid tx"}
	// [ERROR] BroadcastTransaction 1! [POST /transactions][400] postTransactionBadRequest  Invalid tx
}
