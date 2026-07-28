package db

// FederationOptedOut reports whether this repository's maintainer asked
// federated instances neither to scan it nor to contact them about it. Every
// path that must honour the request calls this rather than testing the
// column, so a new surface has one thing to reuse.
func (r Repository) FederationOptedOut() bool { return r.FederationOptOutAt != nil }
