package importer

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// ImportSession holds parsed rows in memory under an import session ID.
// Keys exist only in memory and only until commit or expiry.
type ImportSession struct {
	ID        string
	Format    string
	CreatedAt time.Time
	Records   []Record
	Unmatched []UnmatchedLine
}

// SessionStore keeps import sessions in memory with a TTL.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*ImportSession
	ttl      time.Duration
	now      func() time.Time
}

func NewSessionStore(ttl time.Duration) *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*ImportSession),
		ttl:      ttl,
		now:      time.Now,
	}
}

func (s *SessionStore) newID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Create stores a new session and returns it.
func (s *SessionStore) Create(format string, records []Record, unmatched []UnmatchedLine) (*ImportSession, error) {
	id, err := s.newID()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	sess := &ImportSession{ID: id, Format: format, CreatedAt: s.now(), Records: records, Unmatched: unmatched}
	s.sessions[id] = sess
	return sess, nil
}

// Get returns the session, or nil if missing or expired.
func (s *SessionStore) Get(id string) *ImportSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil
	}
	if s.now().Sub(sess.CreatedAt) > s.ttl {
		delete(s.sessions, id)
		return nil
	}
	return sess
}

// UpdateRecords replaces the record slice of an existing session.
func (s *SessionStore) UpdateRecords(id string, records []Record) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return false
	}
	sess.Records = records
	return true
}

// Delete removes the session (called after commit).
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func (s *SessionStore) pruneLocked() {
	now := s.now()
	for id, sess := range s.sessions {
		if now.Sub(sess.CreatedAt) > s.ttl {
			delete(s.sessions, id)
		}
	}
}
