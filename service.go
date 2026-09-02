package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/session"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Service struct {
	usersMu         sync.RWMutex
	users           map[[32]byte]string // sha256(password) -> name
	userNameToHash  map[string][32]byte // name -> sha256(password)
	padding         atomic.TypedValue[*padding.PaddingFactory]
	handler         N.TCPConnectionHandlerEx
	fallbackHandler N.TCPConnectionHandlerEx
	logger          logger.ContextLogger
}

type ServiceConfig struct {
	PaddingScheme   []byte
	Users           []User
	Handler         N.TCPConnectionHandlerEx
	FallbackHandler N.TCPConnectionHandlerEx
	Logger          logger.ContextLogger
}

type User struct {
	Name     string
	Password string
}

func NewService(config ServiceConfig) (*Service, error) {
	service := &Service{
		handler:         config.Handler,
		fallbackHandler: config.FallbackHandler,
		logger:          config.Logger,
		users:           make(map[[32]byte]string),
		userNameToHash:  make(map[string][32]byte),
	}

	if service.handler == nil || service.logger == nil {
		return nil, os.ErrInvalid
	}

	service.users, service.userNameToHash = makeUserIndexes(config.Users)

	if !padding.UpdatePaddingScheme(config.PaddingScheme, &service.padding) {
		return nil, errors.New("incorrect padding scheme format")
	}

	return service, nil
}

// UpdateUsers atomically replaces the entire user set. Equivalent to
// removing every current user and re-adding the given list. Kept for
// callers that already rebuild a full user list each refresh cycle; new
// callers should prefer AddUsers/RemoveUsers for incremental updates.
func (s *Service) UpdateUsers(users []User) {
	newUsers, newName2Hash := makeUserIndexes(users)
	s.usersMu.Lock()
	s.users = newUsers
	s.userNameToHash = newName2Hash
	s.usersMu.Unlock()
}

// AddUsers adds or updates users by Name. If a user with the same Name
// already exists, its previous password hash is removed before inserting
// the new one; AddUsers also works as "rotate password" for an
// existing user. Hashing is performed outside the write lock; the lock
// is held only across the map mutations.
func (s *Service) AddUsers(users []User) {
	if len(users) == 0 {
		return
	}
	pending := make([]struct {
		name string
		hash [32]byte
	}, len(users))
	for i, user := range users {
		pending[i].name = user.Name
		pending[i].hash = sha256.Sum256([]byte(user.Password))
	}

	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	for _, p := range pending {
		if oldName, ok := s.users[p.hash]; ok && oldName != p.name {
			delete(s.userNameToHash, oldName)
		}
		if oldHash, ok := s.userNameToHash[p.name]; ok && oldHash != p.hash {
			delete(s.users, oldHash)
		}
		s.users[p.hash] = p.name
		s.userNameToHash[p.name] = p.hash
	}
}

// RemoveUsers removes users by Name. Unknown names are silently ignored.
func (s *Service) RemoveUsers(names []string) {
	if len(names) == 0 {
		return
	}
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	for _, name := range names {
		if hash, ok := s.userNameToHash[name]; ok {
			delete(s.users, hash)
			delete(s.userNameToHash, name)
		}
	}
}

func (s *Service) lookupUser(passwordHash [32]byte) (string, bool) {
	s.usersMu.RLock()
	user, ok := s.users[passwordHash]
	s.usersMu.RUnlock()
	return user, ok
}

func makeUserIndexes(users []User) (map[[32]byte]string, map[string][32]byte) {
	userByHash := make(map[[32]byte]string, len(users))
	hashByName := make(map[string][32]byte, len(users))
	for _, user := range users {
		hash := sha256.Sum256([]byte(user.Password))
		if oldHash, ok := hashByName[user.Name]; ok && oldHash != hash {
			delete(userByHash, oldHash)
		}
		if oldName, ok := userByHash[hash]; ok && oldName != user.Name {
			delete(hashByName, oldName)
		}
		userByHash[hash] = user.Name
		hashByName[user.Name] = hash
	}
	return userByHash, hashByName
}

// NewConnection `conn` should be plaintext
func (s *Service) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	b := buf.NewPacket()
	defer b.Release()

	n, err := b.ReadOnceFrom(conn)
	if err != nil {
		return err
	}
	conn = bufio.NewCachedConn(conn, b)

	by, err := b.ReadBytes(32)
	if err != nil {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, err, onClose)
	}
	var passwordSha256 [32]byte
	copy(passwordSha256[:], by)
	if user, ok := s.lookupUser(passwordSha256); ok {
		ctx = auth.ContextWithUser(ctx, user)
	} else {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, E.New("unknown user password"), onClose)
	}
	by, err = b.ReadBytes(2)
	if err != nil {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, E.Extend(err, "read padding length"), onClose)
	}
	paddingLen := binary.BigEndian.Uint16(by)
	if paddingLen > 0 {
		_, err = b.ReadBytes(int(paddingLen))
		if err != nil {
			b.Resize(0, n)
			return s.fallback(ctx, conn, source, E.Extend(err, "read padding"), onClose)
		}
	}

	session := session.NewServerSession(conn, func(stream *session.Stream) {
		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			s.logger.ErrorContext(ctx, "ReadAddrPort:", err)
			return
		}

		s.handler.NewConnectionEx(ctx, stream, source, destination, onClose)
	}, &s.padding, s.logger)
	session.Run()
	session.Close()
	return nil
}

func (s *Service) fallback(ctx context.Context, conn net.Conn, source M.Socksaddr, err error, onClose N.CloseHandlerFunc) error {
	if s.fallbackHandler == nil {
		return E.Extend(err, "fallback disabled")
	}
	s.fallbackHandler.NewConnectionEx(ctx, conn, source, M.Socksaddr{}, onClose)
	return nil
}
