package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
	postgre "aepp-token-migration-backend/postgre_sql"
)

// AddTokenOwner add token owner to DB with given params: eht address, token amount
func AddTokenOwner(router chi.Router, tree *postgre.PostgresMerkleTree) chi.Router {

	router.Post("/owner", addTokenOwner(tree))

	return router
}

func addTokenOwner(tree *postgre.PostgresMerkleTree) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {

		type requestData struct {
			EthAddress string `json:"ethAddress"`
			Balance    string `json:"balance"`
			AeAddress  string `json:"aeAddress"`
		}

		decoder := json.NewDecoder(req.Body)
		var reqData requestData
		err := decoder.Decode(&reqData)
		if err != nil {
			render.JSON(res, req, "Cannot parse request body!")
			return
		}

		if reqData.EthAddress == "" {
			render.JSON(res, req, "Missing ethAddress field!")
			return
		}

		if reqData.Balance == "" {
			render.JSON(res, req, "Invalid balance field!")
			return
		}

		data := fmt.Sprintf("%s%s", reqData.EthAddress, reqData.Balance)
		index, hash := tree.Add([]byte(data), strings.ToLower(reqData.EthAddress), reqData.Balance, reqData.AeAddress)

		fmt.Printf("index: %d, hash: %s\n", index, hash)
		fmt.Printf("root hash: %s\n", tree.Root())

		render.JSON(res, req, fmt.Sprintf("Data was successfully added! index: %d, hash: %s", index, hash))
	}
}
