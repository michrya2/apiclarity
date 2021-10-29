package bfladetector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
)

type AuthzModelRepository interface {
	Load(ctx context.Context, namespace string) (*NamespaceAuthorizationModel, error)
	Store(ctx context.Context, data *NamespaceAuthorizationModel) (*NamespaceAuthorizationModel, error)

	UpdateNrOfTraces(ctx context.Context, namespace string, tracesProcessed int) error
}

func NewFileRepository(baseDir string) AuthzModelRepository {
	return &repository{baseDir: baseDir}
}

type repository struct {
	baseDir string
}

func (r *repository) UpdateNrOfTraces(ctx context.Context, namespace string, tracesProcessed int) error {
	f, err := os.Create(path.Join(r.baseDir, fmt.Sprintf("%s-traces-processed.json", namespace)))
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(tracesProcessed)
}

func (r *repository) Load(ctx context.Context, namespace string) (*NamespaceAuthorizationModel, error) {
	f, err := os.Open(path.Join(r.baseDir, namespace+".json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data := &NamespaceAuthorizationModel{}
	if err := json.NewDecoder(f).Decode(data); err != nil {
		return nil, err
	}
	return data, nil
}

func (r *repository) Store(ctx context.Context, data *NamespaceAuthorizationModel) (*NamespaceAuthorizationModel, error) {
	f, err := os.Create(path.Join(r.baseDir, data.Namespace+".json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(data); err != nil {
		return nil, err
	}
	return data, nil
}
