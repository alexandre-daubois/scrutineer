package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"scrutineer/internal/db"
)

// repoFederationOptOut records or clears the maintainer's request that
// federated instances neither scan this repository nor contact them about
// it. Setting it blocks new scans everywhere the enqueue path reaches. An
// edit that only changes the reason keeps the original request date, since
// that date is what a federated peer is told the request was made on.
func (s *Server) repoFederationOptOut(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	updates := map[string]any{"federation_opt_out_at": nil, "federation_opt_out_reason": ""}
	if r.FormValue("opt_out") != "" {
		at := time.Now().UTC()
		if repo.FederationOptOutAt != nil {
			at = *repo.FederationOptOutAt
		}
		updates["federation_opt_out_at"] = &at
		updates["federation_opt_out_reason"] = strings.TrimSpace(r.FormValue("reason"))
	}
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).Updates(updates).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/repositories/%d", repo.ID))
}
