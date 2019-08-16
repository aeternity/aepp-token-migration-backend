package validator

import (
	"encoding/json"
	
	// "github.com/LimeChain/merkletree"
	// merkletree "aepp-token-migration-backend/memory_merkle_tree"
	merkletree "aepp-token-migration-backend/types"
	
	// "github.com/LimeChain/merkletree/restapi/baseapi"
	baseapi "aepp-token-migration-backend/rest_api/base"
	
	"github.com/go-chi/chi"
	"github.com/go-chi/render"
	"net/http"
	"fmt"
)

// MerkleTreeValidate takes pointer to initialized router and the merkle tree and exposes Rest API routes for getting of status
func MerkleTreeValidate(treeRouter *chi.Mux, tree merkletree.ExternalMerkleTree) *chi.Mux {
	treeRouter.Post("/validate", validate(tree))
	return treeRouter
}

type validateRequest struct {
	Data   string   `json:"data"`
	Index  int      `json:"index"`
	Hashes []string `json:"hashes"`
	EthAddress string `json:"ethAddress"`
	Balance string `json:"balance"`
}

type validateResponse struct {
	baseapi.MerkleAPIResponse
	Exists bool `json:"exists"`
}

func validate(tree merkletree.ExternalMerkleTree) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var b validateRequest
		err := decoder.Decode(&b)
		if err != nil {
			render.JSON(w, r, validateResponse{baseapi.MerkleAPIResponse{Status: false, Error: err.Error()}, false})
			return
		}

		// if b.Data == "" {
		// 	render.JSON(w, r, validateResponse{baseapi.MerkleAPIResponse{Status: false, Error: "Missing data field"}, false})
		// 	return
		// }

		if b.EthAddress == "" {
			render.JSON(w, r, validateResponse{baseapi.MerkleAPIResponse{Status: false, Error: "Missing 'ethAddress' field"}, false})
			return
		}

		if b.Balance == "" {
			render.JSON(w, r, validateResponse{baseapi.MerkleAPIResponse{Status: false, Error: "Missing 'balance' field"}, false})
			return
		}

		mergedData := fmt.Sprintf("%s%s", b.EthAddress, b.Balance)
		// fmt.Println("------> start <--------")
		// fmt.Println(mergedData)
		// fmt.Println("------> end <--------")

		exists, err := tree.ValidateExistence([]byte(mergedData), b.Index, b.Hashes)
		if err != nil {
			render.JSON(w, r, validateResponse{baseapi.MerkleAPIResponse{Status: false, Error: err.Error()}, false})
			return
		}

		render.JSON(w, r, validateResponse{baseapi.MerkleAPIResponse{Status: true, Error: ""}, exists})
	}
}
