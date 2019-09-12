package utils

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	types "aepp-token-migration-backend/types"
)

var isLoaded = false
var envConfig types.EnvConfig

// GetEnvConfig returns env configuration and backendless credentials
func GetEnvConfig() (types.EnvConfig) {

	if isLoaded {
		return envConfig
	}

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	connectionString := os.Getenv("CONNECTION_STRING_POSTGRESQL")
	port, err := strconv.Atoi(os.Getenv("GO_API_PORT"))
	if err != nil {
		log.Fatal("Error parsing port!")
	}

	secretKey := os.Getenv("SECRET_KEY")
	contractRawUrl := os.Getenv("CONTRACT_SOURCE_URL_GIT_RAW")
	aeContractAddress := os.Getenv("AE_CONTRACT_TOKEN_MIGRATION_ADDRESS")
	aeNodeUrl := os.Getenv("AE_NODE_URL")

	// new config
	blLogin := os.Getenv("BACKENDLESS_LOGIN")
	blPassword := os.Getenv("BACKENDLESS_PASSWORD")
	blId := os.Getenv("BACKENDLESS_ID")
	blKey := os.Getenv("BACKENDLESS_KEY")
	blUrl := os.Getenv("BACKENDLESS_URL")
	blUserToken := os.Getenv("BACKENDLESS_USERTOKEN")
	blTable := os.Getenv("BACKENDLESS_TABLE")

	aeNetworkID := os.Getenv("AE_NETWORK_ID")
	aeBackend := os.Getenv("AE_BACKEND")
	aeAbiVersionInt, err := strconv.Atoi(os.Getenv("AE_ABI_VERSION"))
	if err != nil {
		log.Fatal("Error parsing abi version!")
	}

	var aeAbiVersion = uint16(aeAbiVersionInt)

	var backendlessConfig = types.BackendlessConfig{ID: blId, Key: blKey, Login: blLogin, Password: blPassword, Url: blUrl, UserToken: blUserToken, Table: blTable}
	var config = types.EnvConfig{ DbConnectionStr: connectionString, 
		Port: port, 
		SecretKey: secretKey, 
		ContractRawUrl: contractRawUrl, 
		AEContractAddress: aeContractAddress, 
		AENodeUrl: aeNodeUrl, 
		AENetworkID: aeNetworkID,
		AEBackend: aeBackend,
		AEAbiVersion: aeAbiVersion,
		BackendlessConfig: backendlessConfig}

	isLoaded = true
	envConfig = config

	return config
}

func UpdateBackendlessUserToken (userToken string) {

	if userToken != "" {
		envConfig.BackendlessConfig.UserToken = userToken
	}
}
