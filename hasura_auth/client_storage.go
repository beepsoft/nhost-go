package hasura_auth

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"os"
	"sync"
)

type ClientStorage interface {
	SetItem(key string, value string) error
	GetItem(key string) string
}

type FileClientStorage struct {
	FileName string
	mu       sync.Mutex
	store    map[string]string `json:"store"`
}

func NewFileClientStorage(fileName string) (*FileClientStorage, error) {
	storage := FileClientStorage{
		FileName: fileName,
		mu:       sync.Mutex{},
		store:    make(map[string]string),
	}

	storage.readFromFile()
	return &storage, nil
}

func DefaultClientStorage() (*FileClientStorage, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	cs, err := NewFileClientStorage(home + "/.nhost-storage.json")
	if err != nil {
		return nil, err
	}

	return cs, nil
}

func (storage *FileClientStorage) GetItem(key string) string {
	data := storage.store[key]
	return data
}

func (storage *FileClientStorage) SetItem(key string, value string) error {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	storage.store[key] = value
	return storage.writeToFile()

}

func (storage *FileClientStorage) writeToFile() error {
	jsonData, err := json.Marshal(storage.store)
	if err != nil {
		return err
	}
	err = os.WriteFile(storage.FileName, jsonData, 0644)
	return err
}

func (storage *FileClientStorage) readFromFile() error {
	_, err := os.Stat(storage.FileName)
	if err == nil {
		jsonData, err := os.ReadFile(storage.FileName)
		if err != nil {
			log.Fatal(err)
			return err
		}
		if len(jsonData) != 0 {
			return json.Unmarshal(jsonData, &storage.store)
		}
	}
	return nil
}
