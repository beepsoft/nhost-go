package hasura_auth

import (
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_FileClientStorage(t *testing.T) {
	// Get a temp filename
	f, err := os.CreateTemp(t.TempDir(), "nhost-*.json")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	os.Remove(f.Name())

	log.Infof("Storage file: %s", f.Name())

	storage, err := NewFileClientStorage(f.Name())
	assert.Nil(t, err)

	val := storage.GetItem("song")
	assert.Equal(t, "", val)

	err = storage.SetItem("song", "Yesterday")
	assert.Nil(t, err)

	val = storage.GetItem("song")
	assert.Equal(t, "Yesterday", val)

	err = storage.SetItem("song", "Hey Jude")
	assert.Nil(t, err)

	val = storage.GetItem("song")
	assert.Equal(t, "Hey Jude", val)

	// Load into another storage:
	storage2, err2 := NewFileClientStorage(f.Name())
	assert.Nil(t, err2)
	val = storage2.GetItem("song")
	assert.Equal(t, "Hey Jude", val)
	storage2.SetItem("singer", "Paul")

	// storage 2 has singer
	val = storage2.GetItem("singer")
	assert.Equal(t, "Paul", val)

	// storage 1 does not have singer
	val = storage.GetItem("singer")
	assert.Equal(t, "", val)
}
