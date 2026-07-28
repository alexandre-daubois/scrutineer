package db

import (
	"time"

	"gorm.io/gorm"
)

// FederationNotOptedOut is the SQL predicate for a repository whose
// maintainer has not asked federated instances to leave it alone. Every
// query that must honour an opt-out shares this text so a sixth surface
// cannot be written with a subtly different one.
const FederationNotOptedOut = "repositories.federation_opt_out_at IS NULL"

// FederationOptedOut reports whether this repository's maintainer asked
// federated instances neither to scan it nor to contact them. The Go-side
// counterpart of FederationNotOptedOut, for the paths that hold a loaded
// row rather than a query.
func (r Repository) FederationOptedOut() bool { return r.FederationOptOutAt != nil }

// SetDisclosureChannel writes a repository's disclosure channel and, only
// when the value actually changes, stamps DisclosureChannelAt. That
// timestamp is published as verified_at on the interchange route record, so
// bumping it on an unchanged re-write would rewrite the record and churn
// the public feed with no new information.
func SetDisclosureChannel(gdb *gorm.DB, repoID uint, old, value string) error {
	updates := map[string]any{"disclosure_channel": value}
	if old != value {
		now := time.Now().UTC()
		updates["disclosure_channel_at"] = &now
	}
	return gdb.Model(&Repository{}).Where("id = ?", repoID).Updates(updates).Error
}
