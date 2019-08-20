package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"

	memory "aepp-token-migration-backend/memory_merkle_tree"
	db "aepp-token-migration-backend/postgre_sql"
	baseapi "aepp-token-migration-backend/rest_api/base"
	"aepp-token-migration-backend/rest_api/validator"
	"aepp-token-migration-backend/rest_api/owner"
)

func main() {
	connectionString, port, secretKey, contractRawUrl, aeContractAddress, aeNodeUrl := loadEnv()
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

	// add token owner to DB with given params: eht address, token amount
	owner.AddTokenOwner(router, tree)
	
	// gets hash at index 'X'
	baseapi.GetHashByLeafIndex(router, tree)

	// gets info by eth address
	baseapi.GetInfoByEthAddress(router, tree)

	// migrate gets additional info like hash, index, number of tokens by eth address
	baseapi.Migrate(router, tree, secretKey, contractSource, aeContractAddress, aeNodeUrl)

	fmt.Printf("Server start on port: %d\n", port)
	strPort := fmt.Sprintf(":%d", port)
	err := http.ListenAndServe(strPort, router)
	if err != nil {
		fmt.Printf("Server cannot start has ERROR: %s", err)
	}
}

func loadEnv() (connectrinStr string, port int, secretKey string, contractRawUrl string, aeContractAddress string, aeNodeUrl string) {
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
	aeNodeUrl = os.Getenv("AE_NODE_URL")

	return connectionString, port, secretKey, contractRawUrl, aeContractAddress, aeNodeUrl
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