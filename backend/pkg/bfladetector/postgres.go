package bfladetector

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/apiclarity/apiclarity/backend/pkg/database"
)

func init() {
	if err := database.DB.AutoMigrate(&NamespaceAuthorizationModels{}); err != nil {
		log.Fatalf("Failed to run auto migration for Authorization Model: %v", err)
	}
}

const (
	authzModelTableName = "api_authzmodels"

	authzModelNamespaceColumnName       = "namespace"
	authzModelTracesProcessedColumnName = "traces_processed"
)

type NamespaceAuthorizationModels struct {
	ID              uint      `json:"id" gorm:"primarykey"`
	FirstTraceAt    time.Time `json:"first_trace_at" gorm:"column:first_trace_at"`
	LearningEndedAt time.Time `json:"learning_ended_at" gorm:"column:learning_ended_at"`
	Namespace       string    `json:"namespace" gorm:"column:namespace"`
	TracesProcessed int       `json:"traces_processed" gorm:"column:traces_processed"`
	Services        Services  `json:"services" gorm:"column:services"`
}

func (NamespaceAuthorizationModels) TableName() string {
	return authzModelTableName
}

type Services map[string]*AuthorizationModel

// GormDataType gorm common data type
func (Services) GormDataType() string { return "json" }

func (Services) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	switch db.Dialector.Name() {
	case "sqlite":
		return "JSON"
	case "mysql":
		return "JSON"
	case "postgres":
		return "JSONB"
	}
	return ""
}

func (s *Services) Value() (driver.Value, error) {
	if s == nil {
		return nil, nil
	}
	return json.Marshal(s)
}

func (s *Services) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	var buff []byte
	switch v := value.(type) {
	case []byte:
		buff = v
	case string:
		buff = []byte(v)
	default:
		return fmt.Errorf("failed to unmarshal JSONB value: %v", value)
	}

	result := Services{}
	err := json.Unmarshal(buff, &result)
	*s = result
	return err
}

func NewAuthZModelRepository(db *gorm.DB) *authzModelRepository {
	return &authzModelRepository{table: db.Table(authzModelTableName)}
}

type authzModelRepository struct {
	table *gorm.DB
}

func (a authzModelRepository) Load(ctx context.Context, namespace string) (*NamespaceAuthorizationModel, error) {
	data := &NamespaceAuthorizationModels{}
	tx := database.FilterIs(a.table, authzModelNamespaceColumnName, []string{namespace})
	tx = a.table.WithContext(ctx).First(data)
	if tx.Error != nil {
		return nil, tx.Error
	}

	return &NamespaceAuthorizationModel{
		ID:              data.ID,
		FirstTraceAt:    data.FirstTraceAt,
		LearningEndedAt: data.LearningEndedAt,
		Namespace:       data.Namespace,
		TracesProcessed: data.TracesProcessed,
		Services:        data.Services,
	}, nil
}

func (a authzModelRepository) Store(ctx context.Context, data *NamespaceAuthorizationModel) (*NamespaceAuthorizationModel, error) {
	val := &NamespaceAuthorizationModels{
		ID: data.ID, FirstTraceAt: data.FirstTraceAt,
		LearningEndedAt: data.LearningEndedAt, Namespace: data.Namespace,
		TracesProcessed: data.TracesProcessed, Services: data.Services,
	}

	err := a.table.WithContext(ctx).Save(val).Error
	if err != nil {
		return nil, err
	}
	return &NamespaceAuthorizationModel{
		ID: val.ID, FirstTraceAt: val.FirstTraceAt,
		LearningEndedAt: val.LearningEndedAt, Namespace: val.Namespace,
		TracesProcessed: val.TracesProcessed, Services: val.Services,
	}, err
}

func (a authzModelRepository) UpdateNrOfTraces(ctx context.Context, namespace string, tracesProcessed int) error {
	return a.table.WithContext(ctx).
		Where(fmt.Sprintf("%s = ?", authzModelNamespaceColumnName), namespace).
		UpdateColumn(authzModelTracesProcessedColumnName, tracesProcessed).Error
}

type BFLAOpenAPIProvider struct{}

func (d BFLAOpenAPIProvider) GetOpenAPI(serviceName string) (spec io.Reader, err error) {
	invInfo, err := database.GetAPIInventoryByName(serviceName)
	if err != nil {
		return nil, err
	}

	if invInfo.HasProvidedSpec {
		spec = bytes.NewBufferString(invInfo.ProvidedSpec)
	} else if invInfo.HasReconstructedSpec {
		spec = bytes.NewBufferString(invInfo.ReconstructedSpec)
	} else {
		return nil, fmt.Errorf("unable to find OpenAPI spec for service: %q", serviceName)
	}
	return
}
