package main

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi"

	memory "aepp-token-migration-backend/merkle_tree"
	"aepp-token-migration-backend/middleware"
	db "aepp-token-migration-backend/postgre_sql"
	baseapi "aepp-token-migration-backend/rest_api/base"
	"aepp-token-migration-backend/rest_api/owner"
	"aepp-token-migration-backend/rest_api/import"
	"aepp-token-migration-backend/rest_api/validator"
	appUtils "aepp-token-migration-backend/utils"
)

func main() {
	envConfig := appUtils.GetEnvConfig()

	contractSource := appUtils.GetContractSource(envConfig.ContractRawUrl)

	tree := db.LoadMerkleTree(memory.NewMerkleTree(), envConfig.DbConnectionStr)

	// log merkle tree nodes and leafs hashes
	fmt.Printf("root hash: %s\n", tree.Root())

	router := chi.NewRouter()

	middleware.SetCors(router)

	baseapi.MerkleTreeStatus(router, tree.FullMerkleTree)
	baseapi.MerkleTreeHashes(router, tree.FullMerkleTree)
	validator.MerkleTreeValidate(router, tree.FullMerkleTree)
	importapi.ImportMigrationStatus(router, tree)

	// add token owner to DB with given params: eht address, token amount
	owner.AddTokenOwner(router, tree, envConfig.BearerAuthToken)

	// gets hash at index 'X'
	baseapi.GetHashByLeafIndex(router, tree)

	// gets info by eth address
	baseapi.GetInfoByEthAddress(router, tree)

	// migrate gets additional info like hash, index, number of tokens by eth address
	baseapi.Migrate(router, tree, envConfig.SecretKey, contractSource, envConfig)

	fmt.Printf("Server start on port: %d\n", envConfig.Port)
	strPort := fmt.Sprintf(":%d", envConfig.Port)
	err := http.ListenAndServe(strPort, router)
	if err != nil {
		fmt.Printf("Server cannot start has ERROR: %s", err)
	}
}
