// TODO: should be deleted after dev work
package temp

import (
	postgre "aepp-token-migration-backend/postgre_sql"
	appUtils "aepp-token-migration-backend/utils"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

// ResetMirgationStatus developer test function
func ResetMirgationStatus(router chi.Router, tree *postgre.PostgresMerkleTree) chi.Router {

	router.Get("/reset/{ethAddress}", resetMirgationStatus(tree))

	return router
}

func resetMirgationStatus(tree *postgre.PostgresMerkleTree) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		type res struct {
			Reseted bool `json:"reset"`
		}

		ethAddress := chi.URLParam(req, "ethAddress")
		if ethAddress == "" {
			appUtils.LogRequest(req, fmt.Sprintf("/info/%s", "missing_eth_address"))
			http.Error(w, "Invalid request! Missing eth address!", 400)
			return
		}

		appUtils.LogRequest(req, fmt.Sprintf("/reset/%s", ethAddress))

		tree.ResetMigrationStatus(strings.ToLower(ethAddress))

		render.JSON(w, req, res{Reseted: true})
	}
}
