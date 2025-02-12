package context

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func generateHash() string {
	h := sha256.New()
	h.Write([]byte("test"))
	return hex.EncodeToString(h.Sum(nil))
}

func TestBuildRouteFromURI(t *testing.T) {
	t.Run("it returns / for root URLs", func(t *testing.T) {
		assert.Equal(t, BuildRouteFromURI("/"), "/")
	})

	t.Run("it replaces numbers", func(t *testing.T) {
		assert.Equal(t, BuildRouteFromURI("/posts/3"), "/posts/:number")
		assert.Equal(t, BuildRouteFromURI("/posts/3"), "/posts/:number")
		assert.Equal(t, BuildRouteFromURI("/posts/3/"), "/posts/:number")
		assert.Equal(t, BuildRouteFromURI("/posts/3/comments/10"), "/posts/:number/comments/:number")
		assert.Equal(t, BuildRouteFromURI("/blog/2023/05/great-article"), "/blog/:number/:number/great-article")
	})

	t.Run("it replaces dates", func(t *testing.T) {
		assert.Equal(t, BuildRouteFromURI("/posts/2023-05-01"), "/posts/:date")
		assert.Equal(t, BuildRouteFromURI("/posts/2023-05-01/"), "/posts/:date")
		assert.Equal(t, BuildRouteFromURI("/posts/2023-05-01/comments/2023-05-01"), "/posts/:date/comments/:date")
		assert.Equal(t, BuildRouteFromURI("/posts/01-05-2023"), "/posts/:date")
	})

	t.Run("it ignores comma numbers", func(t *testing.T) {
		assert.Equal(t, BuildRouteFromURI("/posts/3,000"), "/posts/3,000")
	})

	t.Run("it ignores API version numbers", func(t *testing.T) {
		assert.Equal(t, BuildRouteFromURI("/v1/posts/3"), "/v1/posts/:number")
	})

	t.Run("it replaces UUIDs", func(t *testing.T) {
		uuids := []string{
			"d9428888-122b-11e1-b85c-61cd3cbb3210",
			"000003e8-2363-21ef-b200-325096b39f47",
			"a981a0c2-68b1-35dc-bcfc-296e52ab01ec",
			"109156be-c4fb-41ea-b1b4-efe1671c5836",
			"90123e1c-7512-523e-bb28-76fab9f2f73d",
			"1ef21d2f-1207-6660-8c4f-419efbd44d48",
			"017f22e2-79b0-7cc3-98c4-dc0c0c07398f",
			"0d8f23a0-697f-83ae-802e-48f3756dd581",
		}
		for _, id := range uuids {
			assert.Equal(t, BuildRouteFromURI("/posts/"+id), "/posts/:uuid")
		}
	})

	t.Run("it ignores invalid UUIDs", func(t *testing.T) {
		assert.Equal(t, BuildRouteFromURI("/posts/00000000-0000-1000-6000-000000000000"), "/posts/00000000-0000-1000-6000-000000000000")
	})

	t.Run("it ignores strings", func(t *testing.T) {
		assert.Equal(t, BuildRouteFromURI("/posts/abc"), "/posts/abc")
	})
	t.Run("it replaces email addresses", func(t *testing.T) {
		assert.Equal(t, BuildRouteFromURI("/login/john.doe@acme.com"), "/login/:email")
		assert.Equal(t, BuildRouteFromURI("/login/john.doe+alias@acme.com"), "/login/:email")
	})

	t.Run("it replaces IP addresses", func(t *testing.T) {
		assert.Equal(t, BuildRouteFromURI("/block/1.2.3.4"), "/block/:ip")
		assert.Equal(t, BuildRouteFromURI("/block/2001:2:ffff:ffff:ffff:ffff:ffff:ffff"), "/block/:ip")
		assert.Equal(t, BuildRouteFromURI("/block/64:ff9a::255.255.255.255"), "/block/:ip")
		assert.Equal(t, BuildRouteFromURI("/block/100::"), "/block/:ip")
		assert.Equal(t, BuildRouteFromURI("/block/fec0::"), "/block/:ip")
		assert.Equal(t, BuildRouteFromURI("/block/227.202.96.196"), "/block/:ip")
	})

	t.Run("it replaces hashes", func(t *testing.T) {
		assert.Equal(t, BuildRouteFromURI("/files/"+generateHash()), "/files/:hash")
	})

	t.Run("it replaces secrets", func(t *testing.T) {
		assert.Equal(t, BuildRouteFromURI("/confirm/CnJ4DunhYfv2db6T1FRfciRBHtlNKOYrjoz"), "/confirm/:secret")
	})

	t.Run("it replaces BSON ObjectIDs", func(t *testing.T) {
		objectID := "66ec29159d00113616fc7184" // Example BSON ObjectID
		assert.Equal(t, BuildRouteFromURI("/posts/"+objectID), "/posts/:objectId")
	})

	t.Run("it replaces ULID strings", func(t *testing.T) {
		assert.Equal(t, BuildRouteFromURI("/posts/01ARZ3NDEKTSV4RRFFQ69G5FAV"), "/posts/:ulid")
		assert.Equal(t, BuildRouteFromURI("/posts/01arz3ndektsv4rrffq69g5fav"), "/posts/:ulid")
	})
}
