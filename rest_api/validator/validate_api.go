package validator

import (
	"encoding/json"

	baseapi "aepp-token-migration-backend/rest_api/base"
	merkletree "aepp-token-migration-backend/types"
	"aepp-token-migration-backend/utils"

	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

type validateRequest struct {
	Data       string   `json:"data"`
	Index      int      `json:"index"`
	Hashes     []string `json:"hashes"`
	EthAddress string   `json:"ethAddress"`
	Balance    string   `json:"balance"`
}

type validateResponse struct {
	baseapi.MerkleAPIResponse
	Exists bool `json:"exists"`
}

// MerkleTreeValidate takes pointer to initialized router and the merkle tree and exposes Rest API routes for getting of status
func MerkleTreeValidate(treeRouter *chi.Mux, tree merkletree.ExternalMerkleTree) *chi.Mux {
	treeRouter.Post("/validate", validate(tree))
	return treeRouter
}

func validate(tree merkletree.ExternalMerkleTree) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		utils.LogRequest(r, "/validate")

		decoder := json.NewDecoder(r.Body)
		var reqData validateRequest
		err := decoder.Decode(&reqData)
		if err != nil {
			render.JSON(w, r, validateResponse{baseapi.MerkleAPIResponse{Status: false, Error: err.Error()}, false})
			return
		}

		if reqData.EthAddress == "" {
			render.JSON(w, r, validateResponse{baseapi.MerkleAPIResponse{Status: false, Error: "Missing 'ethAddress' field"}, false})
			return
		}

		if reqData.Balance == "" {
			render.JSON(w, r, validateResponse{baseapi.MerkleAPIResponse{Status: false, Error: "Missing 'balance' field"}, false})
			return
		}

		mergedData := utils.PreHashFormat(reqData.EthAddress, reqData.Balance) // fmt.Sprintf("%s%s", b.EthAddress, b.Balance)

		exists, err := tree.ValidateExistence([]byte(mergedData), reqData.Index, reqData.Hashes)
		if err != nil {
			render.JSON(w, r, validateResponse{baseapi.MerkleAPIResponse{Status: false, Error: err.Error()}, false})
			return
		}

		render.JSON(w, r, validateResponse{baseapi.MerkleAPIResponse{Status: true, Error: ""}, exists})
	}
}
