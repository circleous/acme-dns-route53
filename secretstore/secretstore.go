package secretstore

// SecretStore represents the interface to CRUD certificates
type SecretStore interface {
	// Store represents logic to store the given secret (value) in the given key
	Store(key, value string) error
}
