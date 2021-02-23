// TODO: should be deleted after dev work
package importapi

import (
	postgre "aepp-token-migration-backend/postgre_sql"
	appUtils "aepp-token-migration-backend/utils"
	"fmt"
	"net/http"
	"log"
	"strings"
	"strconv"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

// ImportMigrationStatus developer function
func ImportMigrationStatus(router chi.Router, tree *postgre.PostgresMerkleTree) chi.Router {

	router.Get("/import/{leafIndex}/{hash}/{aeAddress}", importMigrationStatus(tree))

	return router
}

func importMigrationStatus(tree *postgre.PostgresMerkleTree) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		type res struct {
			Imported bool `json:"import"`
		}

		leafIndex, err := strconv.Atoi(chi.URLParam(req, "leafIndex"))
		if err != nil {
		  log.Printf("Missing 'leafIndex' field! %s\n", err)
      http.Error(w, "Missing 'leafIndex' field!", 400)
		  return
		}
		hash := chi.URLParam(req, "hash")
		aeAddress := chi.URLParam(req, "aeAddress")

		appUtils.LogRequest(req, fmt.Sprintf("/import/%d/%s/%s", leafIndex, hash, aeAddress))

		tree.ImportMigratedToSuccess(leafIndex, hash, strings.ToLower(aeAddress))

		render.JSON(w, req, res{Imported: true})
	}
}
