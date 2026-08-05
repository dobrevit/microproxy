package microproxy

import (
	"crypto/subtle"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// BasicUsers is an in-memory set of users for the Basic scheme. It is safe for
// concurrent use, so a program can add and remove users while the proxy it
// serves is running.
type BasicUsers struct {
	realm string

	mu    sync.RWMutex
	users map[string]string
}

// NewBasicUsers returns an empty user set announcing realm.
func NewBasicUsers(realm string) *BasicUsers {
	return &BasicUsers{realm: realm, users: make(map[string]string)}
}

// Realm implements Credentials.
func (u *BasicUsers) Realm() string { return u.realm }

// Set adds a user or replaces its password.
func (u *BasicUsers) Set(user, password string) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.users[user] = password
}

// Remove drops a user. Connections it has already opened are not affected.
func (u *BasicUsers) Remove(user string) {
	u.mu.Lock()
	defer u.mu.Unlock()

	delete(u.users, user)
}

// Users returns the user names currently known.
func (u *BasicUsers) Users() []string {
	u.mu.RLock()
	defer u.mu.RUnlock()

	users := make([]string, 0, len(u.users))
	for user := range u.users {
		users = append(users, user)
	}

	return users
}

// VerifyBasic implements BasicCredentials. The comparison takes the same time
// whether the user exists or not.
func (u *BasicUsers) VerifyBasic(user, password string) bool {
	u.mu.RLock()
	expected, known := u.users[user]
	u.mu.RUnlock()

	if !known {
		// Compare anyway, so that an unknown user is not distinguishable from
		// a wrong password by how long the answer took.
		expected = strings.Repeat("\x00", len(password))
	}

	return subtle.ConstantTimeCompare([]byte(expected), []byte(password)) == 1 && known
}

// LoadBasicUsers reads the "user:password" lines that htpasswd -p writes.
func LoadBasicUsers(realm string, r io.Reader) (*BasicUsers, error) {
	records, err := readColonSeparated(r)
	if err != nil {
		return nil, err
	}

	users := NewBasicUsers(realm)

	for _, record := range records {
		if len(record) != 2 {
			return nil, errors.New("invalid basic auth file format, expected 'user:password' lines")
		}
		users.Set(record[0], record[1])
	}

	if len(users.users) == 0 {
		return nil, errors.New("auth file contains no data")
	}

	return users, nil
}

// LoadBasicUsersFile reads a file in the format LoadBasicUsers accepts.
func LoadBasicUsersFile(realm, path string) (*BasicUsers, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return LoadBasicUsers(realm, file)
}

// DigestUsers is an in-memory set of users for the Digest scheme, keyed by user
// and realm. It is safe for concurrent use.
//
// Digest never sees the password, only HA1 = MD5(user:realm:password), which is
// what this store keeps.
type DigestUsers struct {
	realm string

	mu  sync.RWMutex
	ha1 map[string]string
}

// NewDigestUsers returns an empty user set announcing realm.
func NewDigestUsers(realm string) *DigestUsers {
	return &DigestUsers{realm: realm, ha1: make(map[string]string)}
}

// Realm implements Credentials.
func (u *DigestUsers) Realm() string { return u.realm }

// Set adds a user, deriving HA1 from the password for this store's realm.
func (u *DigestUsers) Set(user, password string) {
	u.SetHA1(user, u.realm, DigestHA1(user, u.realm, password))
}

// SetHA1 adds a user whose HA1 was computed elsewhere, which is how an htdigest
// file and any store that never held the password are loaded.
func (u *DigestUsers) SetHA1(user, realm, ha1 string) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.ha1[user+":"+realm] = ha1
}

// Remove drops a user from this store's realm.
func (u *DigestUsers) Remove(user string) {
	u.mu.Lock()
	defer u.mu.Unlock()

	delete(u.ha1, user+":"+u.realm)
}

// HA1 implements DigestCredentials.
func (u *DigestUsers) HA1(user, realm string) (string, bool) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	ha1, known := u.ha1[user+":"+realm]

	return ha1, known
}

// DigestHA1 computes MD5(user:realm:password), the digest a Digest exchange is
// verified against.
func DigestHA1(user, realm, password string) string {
	return md5hex(user + ":" + realm + ":" + password)
}

// LoadDigestUsers reads the "user:realm:ha1" lines that htdigest writes.
func LoadDigestUsers(realm string, r io.Reader) (*DigestUsers, error) {
	records, err := readColonSeparated(r)
	if err != nil {
		return nil, err
	}

	users := NewDigestUsers(realm)

	for _, record := range records {
		if len(record) != 3 {
			return nil, errors.New("invalid htdigest file format, expected 'user:realm:ha1' lines")
		}
		users.SetHA1(record[0], record[1], record[2])
	}

	return users, nil
}

// LoadDigestUsersFile reads a file in the format LoadDigestUsers accepts.
func LoadDigestUsersFile(realm, path string) (*DigestUsers, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return LoadDigestUsers(realm, file)
}

func readColonSeparated(r io.Reader) ([][]string, error) {
	reader := csv.NewReader(r)
	reader.Comma = ':'
	reader.Comment = '#'
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("couldn't read the credentials: %w", err)
	}

	return records, nil
}

// basicFunc lets a program authenticate against a store of its own without
// implementing an interface.
type basicFunc struct {
	realm  string
	verify func(user, password string) bool
}

func (f basicFunc) Realm() string { return f.realm }

func (f basicFunc) VerifyBasic(user, password string) bool { return f.verify(user, password) }

// BasicCredentialsFunc turns a verification function into credentials for the
// Basic scheme. verify is called from the goroutine serving the request and has
// to be safe for concurrent use.
func BasicCredentialsFunc(realm string, verify func(user, password string) bool) BasicCredentials {
	return basicFunc{realm: realm, verify: verify}
}

// digestFunc is the Digest counterpart of basicFunc.
type digestFunc struct {
	realm string
	ha1   func(user, realm string) (string, bool)
}

func (f digestFunc) Realm() string { return f.realm }

func (f digestFunc) HA1(user, realm string) (string, bool) { return f.ha1(user, realm) }

// DigestCredentialsFunc turns an HA1 lookup into credentials for the Digest
// scheme. ha1 is called from the goroutine serving the request and has to be
// safe for concurrent use.
func DigestCredentialsFunc(realm string, ha1 func(user, realm string) (string, bool)) DigestCredentials {
	return digestFunc{realm: realm, ha1: ha1}
}
