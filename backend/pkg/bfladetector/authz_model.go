package bfladetector

import (
	"github.com/apiclarity/apiclarity/api/server/models"
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

func (ops Operations) Find(fn func(op *Operation) bool) *Operation {
	for _, op := range ops {
		if fn(op) {
			return op
		}
	}
	return nil
}

type Audience []*ServiceAccount

func (aud Audience) Find(fn func(sa *ServiceAccount) bool) *ServiceAccount {
	for _, sa := range aud {
		if fn(sa) {
			return sa
		}
	}
	return nil
}

type NamespaceAuthorizationModel struct {
	ID              uint                           `json:"id"`
	FirstTraceAt    time.Time                      `json:"first_trace_at"`
	LearningEndedAt time.Time                      `json:"learning_ended_at"`
	Namespace       string                         `json:"namespace"`
	TracesProcessed int                            `json:"traces_processed"`
	Services        map[string]*AuthorizationModel `json:"services"`
}
