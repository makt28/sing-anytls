package anytls

import (
	"context"
	"crypto/sha256"
	"net"
	"sync"
	"testing"

	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type nopHandler struct{}

func (nopHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
}

func newTestService(t *testing.T, users []User) *Service {
	t.Helper()
	service, err := NewService(ServiceConfig{
		PaddingScheme: padding.DefaultPaddingScheme,
		Users:         users,
		Handler:       nopHandler{},
		Logger:        logger.NOP(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func hashPassword(password string) [32]byte {
	return sha256.Sum256([]byte(password))
}

func TestAddUsersAddsAndRotatesPassword(t *testing.T) {
	service := newTestService(t, []User{{Name: "u1", Password: "old"}})

	if user, ok := service.lookupUser(hashPassword("old")); !ok || user != "u1" {
		t.Fatalf("lookup old password = %q, %v; want u1, true", user, ok)
	}

	service.AddUsers([]User{{Name: "u1", Password: "new"}, {Name: "u2", Password: "two"}})

	if _, ok := service.lookupUser(hashPassword("old")); ok {
		t.Fatal("old password still authenticates after rotation")
	}
	if user, ok := service.lookupUser(hashPassword("new")); !ok || user != "u1" {
		t.Fatalf("lookup new password = %q, %v; want u1, true", user, ok)
	}
	if user, ok := service.lookupUser(hashPassword("two")); !ok || user != "u2" {
		t.Fatalf("lookup second user = %q, %v; want u2, true", user, ok)
	}
}

func TestRemoveUsersDeletesByName(t *testing.T) {
	service := newTestService(t, []User{
		{Name: "u1", Password: "one"},
		{Name: "u2", Password: "two"},
	})

	service.RemoveUsers([]string{"u1", "unknown"})

	if _, ok := service.lookupUser(hashPassword("one")); ok {
		t.Fatal("removed user still authenticates")
	}
	if user, ok := service.lookupUser(hashPassword("two")); !ok || user != "u2" {
		t.Fatalf("remaining user lookup = %q, %v; want u2, true", user, ok)
	}
}

func TestUpdateUsersReplacesAllUsers(t *testing.T) {
	service := newTestService(t, []User{{Name: "u1", Password: "one"}})

	service.UpdateUsers([]User{{Name: "u2", Password: "two"}})

	if _, ok := service.lookupUser(hashPassword("one")); ok {
		t.Fatal("old full-list user still authenticates after UpdateUsers")
	}
	if user, ok := service.lookupUser(hashPassword("two")); !ok || user != "u2" {
		t.Fatalf("new full-list user lookup = %q, %v; want u2, true", user, ok)
	}
}

func TestUpdateUsersKeepsIndexesConsistentForDuplicateNames(t *testing.T) {
	service := newTestService(t, nil)

	service.UpdateUsers([]User{
		{Name: "u1", Password: "old"},
		{Name: "u1", Password: "new"},
	})

	if _, ok := service.lookupUser(hashPassword("old")); ok {
		t.Fatal("old duplicate-name password still authenticates")
	}
	if user, ok := service.lookupUser(hashPassword("new")); !ok || user != "u1" {
		t.Fatalf("lookup new duplicate-name password = %q, %v; want u1, true", user, ok)
	}
}

func TestAddUsersKeepsIndexesConsistentForDuplicatePassword(t *testing.T) {
	service := newTestService(t, []User{{Name: "u1", Password: "shared"}})

	service.AddUsers([]User{{Name: "u2", Password: "shared"}})

	if user, ok := service.lookupUser(hashPassword("shared")); !ok || user != "u2" {
		t.Fatalf("lookup shared password = %q, %v; want u2, true", user, ok)
	}

	service.RemoveUsers([]string{"u1"})
	if user, ok := service.lookupUser(hashPassword("shared")); !ok || user != "u2" {
		t.Fatalf("removing old duplicate-password owner removed active user: %q, %v", user, ok)
	}
}

func TestConcurrentUserUpdatesAndLookups(t *testing.T) {
	service := newTestService(t, []User{{Name: "u0", Password: "p0"}})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				service.AddUsers([]User{{Name: "u1", Password: "p1"}, {Name: "u2", Password: "p2"}})
				service.lookupUser(hashPassword("p1"))
				service.RemoveUsers([]string{"u2"})
				service.UpdateUsers([]User{{Name: "u0", Password: "p0"}, {Name: "u1", Password: "p1"}})
				service.lookupUser(hashPassword("missing"))
			}
		}()
	}
	wg.Wait()
}
