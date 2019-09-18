package owner

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	postgre "aepp-token-migration-backend/postgre_sql"
	"aepp-token-migration-backend/utils"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

// AddTokenOwner add token owner to DB with given params: eht address, token amount
func AddTokenOwner(router chi.Router, tree *postgre.PostgresMerkleTree, bearerAuthToken string) chi.Router {

	router.Post("/owner", addTokenOwner(tree, bearerAuthToken))

	return router
}

func addTokenOwner(tree *postgre.PostgresMerkleTree, bearerAuthToken string) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {

		auth := req.Header.Get("Authorization")
		if auth == "" || auth != bearerAuthToken {
			http.Error(res, "Unauthorized", 401)
			return
		}

		utils.LogRequest(req, "/owner")

		type requestData struct {
			EthAddress string `json:"ethAddress"`
			Balance    string `json:"balance"`
			AeAddress  string `json:"aeAddress"`
		}

		decoder := json.NewDecoder(req.Body)
		var reqData requestData
		err := decoder.Decode(&reqData)
		if err != nil {
			log.Printf("Cannot parse request body! %s\n", err)
			http.Error(res, "Cannot parse request body!", 400)
			return
		}

		if reqData.EthAddress == "" {
			log.Printf("Missing 'ethAddress' field! %s\n", err)
			http.Error(res, "Missing 'ethAddress' field!", 400)
			return
		}

		if reqData.Balance == "" {
			log.Printf("Invalid 'balance' field! %s\n", err)
			http.Error(res, "Invalid 'balance' field!", 400)
			return
		}

		data := utils.PreHashFormat(reqData.EthAddress, reqData.Balance)
		index, hash := tree.Add([]byte(data), strings.ToLower(reqData.EthAddress), reqData.Balance, reqData.AeAddress)

		type addOwnerResponse struct {
			Index int `json:"index"`
			Hash string `json:"hash"`
			Message string `json:"message"`
		}

		render.JSON(res, req, addOwnerResponse{index, hash, "Data was successfully added!"})
	}
}
