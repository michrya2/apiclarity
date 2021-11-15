package bfladetector

import (
	"github.com/apiclarity/apiclarity/api/server/models"
	"github.com/go-openapi/strfmt"
	"time"
)

type Operation struct {
	Method   string   `json:"method"`
	Path     string   `json:"path"`
	Audience Audience `json:"audience"`
}

type ServiceAccount struct {
	Name      string               `json:"name"`
	K8sObject *models.K8sObjectRef `json:"k8s_object"`
}

type AuthorizationModel struct {
	ServiceName string               `json:"service_name"`
	K8sObject   *models.K8sObjectRef `json:"k8s_object"`
	Operations  Operations           `json:"operations"`
}

type Operations []*Operation

func (ops Operations) Find(fn func(op *Operation) bool) (int, *Operation) {
	for i, op := range ops {
		if fn(op) {
			return i, op
		}
	}
	return 0, nil
}

type Audience []*ServiceAccount

func (aud Audience) Find(fn func(sa *ServiceAccount) bool) (int, *ServiceAccount) {
	for i, sa := range aud {
		if fn(sa) {
			return i, sa
		}
	}
	return 0, nil
}

type NamespaceAuthorizationModel struct {
	ID              uint                           `json:"id"`
	FirstTraceAt    time.Time                      `json:"first_trace_at"`
	LearningEndedAt time.Time                      `json:"learning_ended_at"`
	Namespace       string                         `json:"namespace"`
	TracesProcessed int                            `json:"traces_processed"`
	Services        map[string]*AuthorizationModel `json:"services"`
}

func (n *NamespaceAuthorizationModel) ToModel() *models.AuthorizationModel {
	services := map[string]models.AuthorizationModelService{}
	for svcName, svc := range n.Services {
		ams := models.AuthorizationModelService{
			K8sObject:   svc.K8sObject,
			ServiceName: svc.ServiceName,
		}
		for _, op := range svc.Operations {
			operation := &models.AuthorizationModelOperation{
				Method: op.Method,
				Path:   op.Path,
			}
			for _, audience := range op.Audience {
				operation.Audience = append(operation.Audience, &models.AuthorizationModelAudience{
					K8sObject: audience.K8sObject,
					Name:      audience.Name,
				})
			}
			ams.Operations = append(ams.Operations, operation)
		}
		services[svcName] = ams
	}
	return &models.AuthorizationModel{
		ID:              int64(n.ID),
		FirstTraceAt:    strfmt.DateTime(n.FirstTraceAt),
		LearningEndedAt: strfmt.DateTime(n.LearningEndedAt),
		Namespace:       n.Namespace,
		TracesProcessed: int64(n.TracesProcessed),
		Services:        services,
	}
}
