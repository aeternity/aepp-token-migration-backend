package owner

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	postgre "aepp-token-migration-backend/postgre_sql"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
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

		data := fmt.Sprintf("%s%s", reqData.EthAddress, reqData.Balance)
		index, hash := tree.Add([]byte(data), strings.ToLower(reqData.EthAddress), reqData.Balance, reqData.AeAddress)

		render.JSON(res, req, fmt.Sprintf("Data was successfully added! index: %d, hash: %s", index, hash))
	}
}
