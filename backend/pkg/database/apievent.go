// Copyright © 2021 Cisco Systems, Inc. and its affiliates.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package database

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/apiclarity/apiclarity/api/server/models"
	"github.com/apiclarity/apiclarity/api/server/restapi/operations"
	"github.com/apiclarity/apiclarity/backend/pkg/utils"
	speculatorspec "github.com/apiclarity/speculator/pkg/spec"
)

const (
	apiEventTableName = "api_events"

	// NOTE: when changing one of the column names change also the gorm label in APIEvent.
	timeColumnName                 = "time"
	methodColumnName               = "method"
	pathColumnName                 = "path"
	providedPathIDColumnName       = "provided_path_id"
	reconstructedPathIDColumnName  = "reconstructed_path_id"
	statusCodeColumnName           = "status_code"
	sourceIPColumnName             = "source_ip"
	destinationIPColumnName        = "destination_ip"
	destinationPortColumnName      = "destination_port"
	hasSpecDiffColumnName          = "has_spec_diff" // hasProvidedSpecDiff || hasReconstructedSpecDiff
	specDiffTypeColumnName         = "spec_diff_type"
	hostSpecNameColumnName         = "host_spec_name"
	newReconstructedSpecColumnName = "new_reconstructed_spec"
	oldReconstructedSpecColumnName = "old_reconstructed_spec"
	newProvidedSpecColumnName      = "new_provided_spec"
	oldProvidedSpecColumnName      = "old_provided_spec"
	apiInfoIDColumnName            = "api_info_id"
	isNonAPIColumnName             = "is_non_api"
	eventTypeColumnName            = "event_type"
	bflaStatusColumnName           = "bfla_status"
	requestIdColumnName            = "request_id"
	destinationK8sObjectColumnName = "destination_k8s_object"
	sourceK8sObjectColumnName      = "source_k8s_object"
)

var specDiffColumns = []string{newReconstructedSpecColumnName, oldReconstructedSpecColumnName, newProvidedSpecColumnName, oldProvidedSpecColumnName}

type APIEvent struct {
	// will be populated after inserting to DB
	ID        uint   `gorm:"primarykey" faker:"-"`
	RequestID string `gorm:"index:request_id,unique"`
	// CreatedAt time.Time
	// UpdatedAt time.Time

	Time                     strfmt.DateTime   `json:"time" gorm:"column:time" faker:"-"`
	Method                   models.HTTPMethod `json:"method,omitempty" gorm:"column:method" faker:"oneof: GET, PUT, POST, DELETE"`
	Path                     string            `json:"path,omitempty" gorm:"column:path" faker:"oneof: /news, /customers, /jokes"`
	ProvidedPathID           string            `json:"providedPathId,omitempty" gorm:"column:provided_path_id" faker:"-"`
	ReconstructedPathID      string            `json:"reconstructedPathId,omitempty" gorm:"column:reconstructed_path_id" faker:"-"`
	Query                    string            `json:"query,omitempty" gorm:"column:query" faker:"oneof: name=ferret&color=purple, foo=bar, -"`
	StatusCode               int64             `json:"statusCode,omitempty" gorm:"column:status_code" faker:"oneof: 200, 401, 404, 500"`
	SourceIP                 string            `json:"sourceIP,omitempty" gorm:"column:source_ip" faker:"sourceIP"`
	DestinationIP            string            `json:"destinationIP,omitempty" gorm:"column:destination_ip" faker:"destinationIP"`
	DestinationPort          int64             `json:"destinationPort,omitempty" gorm:"column:destination_port" faker:"oneof: 80, 443"`
	HasReconstructedSpecDiff bool              `json:"hasReconstructedSpecDiff,omitempty" gorm:"column:has_reconstructed_spec_diff"`
	HasProvidedSpecDiff      bool              `json:"hasProvidedSpecDiff,omitempty" gorm:"column:has_provided_spec_diff"`
	HasSpecDiff              bool              `json:"hasSpecDiff,omitempty" gorm:"column:has_spec_diff"`
	SpecDiffType             models.DiffType   `json:"specDiffType,omitempty" gorm:"column:spec_diff_type" faker:"oneof: ZOMBIE_DIFF, SHADOW_DIFF, GENERAL_DIFF, NO_DIFF"`
	HostSpecName             string            `json:"hostSpecName,omitempty" gorm:"column:host_spec_name" faker:"oneof: test.com, example.com, kaki.org"`
	IsNonAPI                 bool              `json:"isNonApi,omitempty" gorm:"column:is_non_api" faker:"-"`

	// Spec diff info
	// New reconstructed spec json string
	NewReconstructedSpec string `json:"newReconstructedSpec,omitempty" gorm:"column:new_reconstructed_spec" faker:"-"`
	// Old reconstructed spec json string
	OldReconstructedSpec string `json:"oldReconstructedSpec,omitempty" gorm:"column:old_reconstructed_spec" faker:"-"`
	// New provided spec json string
	NewProvidedSpec string `json:"newProvidedSpec,omitempty" gorm:"column:new_provided_spec" faker:"-"`
	// Old provided spec json string
	OldProvidedSpec string `json:"oldProvidedSpec,omitempty" gorm:"column:old_provided_spec" faker:"-"`

	// ID for the relevant APIInfo
	APIInfoID uint `json:"apiInfoId,omitempty" gorm:"column:api_info_id" faker:"-"`
	// We'll not always have a corresponding API info (e.g. non-API resources) so the type is needed also for the event
	EventType models.APIType `json:"eventType,omitempty" gorm:"column:event_type" faker:"oneof: INTERNAL, EXTERNAL"`

	DestinationK8sObject *K8sObjectRef     `json:"destinationK8sObject,omitempty" gorm:"column:destination_k8s_object"`
	SourceK8sObject      *K8sObjectRef     `json:"sourceK8sObject,omitempty" gorm:"column:source_k8s_object"`
	BFLAStatus           models.BFLAStatus `json:"bflaStatus" gorm:"column:bfla_status"`
}

type K8sObjectRef struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Name       string `json:"name,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	UID        string `json:"uid,omitempty"`
}

// GormDataType gorm common data type
func (K8sObjectRef) GormDataType() string { return "json" }

func (K8sObjectRef) GormDBDataType(db *gorm.DB, field *schema.Field) string {
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

func (s *K8sObjectRef) Value() (driver.Value, error) {
	if s == nil {
		return nil, nil
	}
	return json.Marshal(s)
}

func (s *K8sObjectRef) Scan(value interface{}) error {
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

	result := K8sObjectRef{}
	err := json.Unmarshal(buff, &result)
	*s = result
	return err
}

type APIEventsTable interface {
	GetAPIEventsAndTotal(params operations.GetAPIEventsParams) ([]APIEvent, int64, error)
	GetAPIEvent(eventID uint32) (*APIEvent, error)
	GetAPIEventReconstructedSpecDiff(eventID uint32) (*APIEvent, error)
	GetAPIEventProvidedSpecDiff(eventID uint32) (*APIEvent, error)
	SetAPIEventsReconstructedPathID(approvedReview []*speculatorspec.ApprovedSpecReviewPathItem, host string, port string) error
	GetAPIEventsLatestDiffs(latestDiffsNum int) ([]APIEvent, error)
	GetAPIUsages(params operations.GetAPIUsageHitCountParams) ([]*models.HitCount, error)
	GetDashboardAPIUsages(startTime, endTime time.Time, apiType APIUsageType) ([]*models.APIUsage, error)
	CreateAPIEvent(event *APIEvent)
	GroupByAPIInfo() ([]HostGroup, error)
	UpdateAPIEventBFLAStatusByRequestID(requestId string, bflaStatus models.BFLAStatus) error
	UpdateAPIEventBFLAStatusByPathMethodSrcDest(path, method, dest, src string, bflaStatus models.BFLAStatus) error
}

type APIEventsTableHandler struct {
	tx *gorm.DB
}

type HostGroup struct {
	HostSpecName string
	Port         int64
	APIType      string
	APIInfoID    uint32
	Count        int
}

type APIEventsFilters struct {
	DestinationIPIsNot            []string
	DestinationIPIs               []string
	DestinationPortIsNot          []string
	DestinationPortIs             []string
	EndTime                       strfmt.DateTime
	ShowNonAPI                    bool
	HasSpecDiffIs                 *bool
	SpecDiffTypeIs                []string
	MethodIs                      []string
	ReconstructedPathIDIs         []string
	ProvidedPathIDIs              []string
	PathContains                  []string
	PathEnd                       *string
	PathIsNot                     []string
	PathIs                        []string
	PathStart                     *string
	SourceIPIsNot                 []string
	SourceIPIs                    []string
	SpecContains                  []string
	SpecEnd                       *string
	SpecIsNot                     []string
	SpecIs                        []string
	SpecStart                     *string
	StartTime                     strfmt.DateTime
	StatusCodeGte                 *string
	StatusCodeIsNot               []string
	StatusCodeIs                  []string
	StatusCodeLte                 *string
	BflaStatusIs                  []string
	BflaStatusIsNot               []string
	DestinationK8sObjectNameIs    []string
	DestinationK8sObjectNameIsNot []string
	SourceK8sObjectNameIs         []string
	SourceK8sObjectNameIsNot      []string
}

const dashboardTopAPIsNum = 5

func (a *APIEventsTableHandler) GroupByAPIInfo() ([]HostGroup, error) {
	var results []HostGroup

	rows, err := a.tx.
		// filters out non APIs
		Not(isNonAPIColumnName+" = ?", true).
		Select(
			FieldInTable(apiEventTableName, hostSpecNameColumnName) +
				", " + FieldInTable(apiEventTableName, destinationPortColumnName) +
				", " + FieldInTable(apiEventTableName, apiInfoIDColumnName) +
				", " + FieldInTable(apiEventTableName, eventTypeColumnName) +
				", COUNT(*) AS count").
		Group(FieldInTable(apiEventTableName, hostSpecNameColumnName)).
		Group(FieldInTable(apiEventTableName, destinationPortColumnName)).
		Group(FieldInTable(apiEventTableName, apiInfoIDColumnName)).
		Group(FieldInTable(apiEventTableName, eventTypeColumnName)).
		Order("count desc").
		Limit(dashboardTopAPIsNum).Rows()
	if err != nil {
		return nil, fmt.Errorf("failed to get top API event counts: %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Warnf("Failed to close rows: %v", err)
		}
	}()

	for rows.Next() {
		group := HostGroup{}
		if err := rows.Scan(&group.HostSpecName, &group.Port, &group.APIInfoID, &group.APIType, &group.Count); err != nil {
			return nil, fmt.Errorf("failed to get fields: %v", err)
		}
		log.Debugf("Fetched fields: %+v", group)
		results = append(results, group)
	}

	return results, nil
}

func (APIEvent) TableName() string {
	return apiEventTableName
}

func APIEventFromDB(event *APIEvent) *models.APIEvent {
	return &models.APIEvent{
		APIInfoID:                uint32(event.APIInfoID),
		APIType:                  event.EventType,
		DestinationIP:            event.DestinationIP,
		DestinationPort:          event.DestinationPort,
		HasProvidedSpecDiff:      &event.HasProvidedSpecDiff,
		HasReconstructedSpecDiff: &event.HasReconstructedSpecDiff,
		HostSpecName:             event.HostSpecName,
		ID:                       uint32(event.ID),
		Method:                   event.Method,
		Path:                     event.Path,
		Query:                    event.Query,
		SourceIP:                 event.SourceIP,
		SpecDiffType:             &event.SpecDiffType,
		StatusCode:               event.StatusCode,
		Time:                     event.Time,
		DestinationK8sObject:     (*models.K8sObjectRef)(event.DestinationK8sObject),
		SourceK8sObject:          (*models.K8sObjectRef)(event.SourceK8sObject),
		BflaStatus:               event.BFLAStatus,
	}
}

func (a *APIEventsTableHandler) CreateAPIEvent(event *APIEvent) {
	if result := a.tx.Save(event); result.Error != nil {
		log.Errorf("Failed to create event: %v", result.Error)
	} else {
		log.Infof("Event created %+v", event)
	}
}

func (a APIEventsTableHandler) UpdateAPIEventBFLAStatusByRequestID(requestId string, bflaStatus models.BFLAStatus) error {
	retries := 5
	for retries != 0 {
		t := a.tx
		t = FilterIsString(t, requestIdColumnName, requestId)
		t.UpdateColumn(bflaStatusColumnName, bflaStatus)
		if t.Error != nil {
			return t.Error
		}
		if t.RowsAffected == 0 {
			log.Warn("no rows affected, trace not created yet, waiting: 2s")
			time.Sleep(2 * time.Second)
			retries--
			continue
		}
		return nil
	}

	return errors.New("unable to update trace with BFLA status after 5 tries")
}

func (a APIEventsTableHandler) UpdateAPIEventBFLAStatusByPathMethodSrcDest(path, method, dest, src string, bflaStatus models.BFLAStatus) error {
	retries := 5
	for retries != 0 {
		t := a.tx
		t = FilterIsString(t, methodColumnName, method)
		t = FilterIsString(t, pathColumnName, path)
		t = FilterIsString(t, fmt.Sprintf("%s->>'name'", destinationK8sObjectColumnName), dest)
		t = FilterIsString(t, fmt.Sprintf("%s->>'name'", sourceK8sObjectColumnName), src)
		t.UpdateColumn(bflaStatusColumnName, bflaStatus)
		if t.Error != nil {
			return t.Error
		}
		if t.RowsAffected == 0 {
			log.Warn("no rows affected, trace not created yet, waiting: 2s")
			time.Sleep(2 * time.Second)
			retries--
			continue
		}
		return nil
	}

	return errors.New("unable to update trace with BFLA status after 5 tries")
}

func (a *APIEventsTableHandler) GetAPIEventsAndTotal(params operations.GetAPIEventsParams) ([]APIEvent, int64, error) {
	var apiEvents []APIEvent
	var count int64

	tx := a.setAPIEventsFilters(getAPIEventsParamsToFilters(params), true)
	// get total count item with the current filters
	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	sortOrder, err := CreateSortOrder(params.SortKey, params.SortDir)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create sort order: %v", err)
	}
	// get specific page ordered items with the current filters
	if err := tx.Scopes(Paginate(params.Page, params.PageSize)).
		Order(sortOrder).
		Omit(specDiffColumns...).
		Find(&apiEvents).Error; err != nil {
		return nil, 0, err
	}

	return apiEvents, count, nil
}

func (a *APIEventsTableHandler) GetAPIEvent(eventID uint32) (*APIEvent, error) {
	var apiEvent APIEvent

	if err := a.tx.Omit(specDiffColumns...).First(&apiEvent, eventID).Error; err != nil {
		return nil, err
	}

	return &apiEvent, nil
}

func (a *APIEventsTableHandler) GetAPIEventReconstructedSpecDiff(eventID uint32) (*APIEvent, error) {
	var apiEvent APIEvent

	if err := a.tx.Select(newReconstructedSpecColumnName, oldReconstructedSpecColumnName, specDiffTypeColumnName).First(&apiEvent, eventID).Error; err != nil {
		return nil, err
	}

	return &apiEvent, nil
}

func (a *APIEventsTableHandler) GetAPIEventProvidedSpecDiff(eventID uint32) (*APIEvent, error) {
	var apiEvent APIEvent

	if err := a.tx.Select(newProvidedSpecColumnName, oldProvidedSpecColumnName, specDiffTypeColumnName).First(&apiEvent, eventID).Error; err != nil {
		return nil, err
	}

	return &apiEvent, nil
}

func (a *APIEventsTableHandler) GetAPIEventsLatestDiffs(latestDiffsNum int) ([]APIEvent, error) {
	var latestDiffs []APIEvent
	if err := a.tx.Where(hasSpecDiffColumnName + " = true").
		Order("time desc").Limit(latestDiffsNum).Scan(&latestDiffs).Error; err != nil {
		return nil, fmt.Errorf("failed to get latest diffs from events table. %v", err)
	}

	return latestDiffs, nil
}

func (a *APIEventsTableHandler) setAPIEventsFilters(filters *APIEventsFilters, shouldSetTimeFilters bool) *gorm.DB {
	tx := a.tx
	if shouldSetTimeFilters {
		// time filter
		tx = tx.Where(CreateTimeFilter(filters.StartTime, filters.EndTime))
	}

	// methods filter
	tx = FilterIs(tx, methodColumnName, filters.MethodIs)

	// path ID filters
	tx = FilterIs(tx, providedPathIDColumnName, filters.ProvidedPathIDIs)
	tx = FilterIs(tx, reconstructedPathIDColumnName, filters.ReconstructedPathIDIs)

	// path filters
	tx = FilterIs(tx, pathColumnName, filters.PathIs)
	tx = FilterIsNot(tx, pathColumnName, filters.PathIsNot)
	tx = FilterContains(tx, pathColumnName, filters.PathContains)
	tx = FilterStartsWith(tx, pathColumnName, filters.PathStart)
	tx = FilterEndsWith(tx, pathColumnName, filters.PathEnd)

	// status codes filters
	tx = FilterIs(tx, statusCodeColumnName, filters.StatusCodeIs)
	tx = FilterIsNot(tx, statusCodeColumnName, filters.StatusCodeIsNot)
	tx = FilterGte(tx, statusCodeColumnName, filters.StatusCodeGte)
	tx = FilterLte(tx, statusCodeColumnName, filters.StatusCodeLte)

	// source IPs filters
	tx = FilterIs(tx, sourceIPColumnName, filters.SourceIPIs)
	tx = FilterIsNot(tx, sourceIPColumnName, filters.SourceIPIsNot)
	// destination IPs filters
	tx = FilterIs(tx, destinationIPColumnName, filters.DestinationIPIs)
	tx = FilterIsNot(tx, destinationIPColumnName, filters.DestinationIPIsNot)
	// destination ports filters
	tx = FilterIs(tx, destinationPortColumnName, filters.DestinationPortIs)
	tx = FilterIsNot(tx, destinationPortColumnName, filters.DestinationPortIsNot)

	// has spec diff filter
	tx = FilterIsBool(tx, hasSpecDiffColumnName, filters.HasSpecDiffIs)

	// spec diff type filter
	tx = FilterIs(tx, specDiffTypeColumnName, filters.SpecDiffTypeIs)

	// host spec name filters
	tx = FilterIs(tx, hostSpecNameColumnName, filters.SpecIs)
	tx = FilterIsNot(tx, hostSpecNameColumnName, filters.SpecIsNot)
	tx = FilterContains(tx, hostSpecNameColumnName, filters.SpecContains)
	tx = FilterStartsWith(tx, hostSpecNameColumnName, filters.SpecStart)
	tx = FilterEndsWith(tx, hostSpecNameColumnName, filters.SpecEnd)

	// BFLA status filters
	tx = FilterIs(tx, bflaStatusColumnName, filters.BflaStatusIs)
	tx = FilterIsNot(tx, bflaStatusColumnName, filters.BflaStatusIsNot)

	// Destination K8s Object filters
	tx = FilterIs(tx, fmt.Sprintf("%s->>'name'", destinationK8sObjectColumnName), filters.DestinationK8sObjectNameIs)
	tx = FilterIsNot(tx, fmt.Sprintf("%s->>'name'", destinationK8sObjectColumnName), filters.DestinationK8sObjectNameIsNot)

	// Source K8s Object filters
	tx = FilterIs(tx, fmt.Sprintf("%s->>'name'", sourceK8sObjectColumnName), filters.SourceK8sObjectNameIs)
	tx = FilterIsNot(tx, fmt.Sprintf("%s->>'name'", sourceK8sObjectColumnName), filters.SourceK8sObjectNameIsNot)

	// BFLA status filters
	tx = FilterIs(tx, bflaStatusColumnName, filters.BflaStatusIs)
	tx = FilterIsNot(tx, bflaStatusColumnName, filters.BflaStatusIsNot)

	// ignore non APIs
	if !filters.ShowNonAPI {
		tx.Where(fmt.Sprintf("%s = ?", isNonAPIColumnName), false)
	}

	return tx
}

// SetAPIEventsReconstructedPathID will set reconstructed path ID for all events with the provided paths, host and port.
func (a *APIEventsTableHandler) SetAPIEventsReconstructedPathID(approvedReview []*speculatorspec.ApprovedSpecReviewPathItem, host string, port string) error {
	err := a.tx.Transaction(func(tx *gorm.DB) error {
		for _, item := range approvedReview {
			tx := FilterIs(tx, pathColumnName, utils.MapToSlice(item.Paths))
			tx = FilterIs(tx, hostSpecNameColumnName, []string{host})
			tx = FilterIs(tx, destinationPortColumnName, []string{port})

			if err := tx.Model(&APIEvent{}).Updates(map[string]interface{}{reconstructedPathIDColumnName: item.PathUUID}).Error; err != nil {
				// return any error will rollback
				return err
			}
		}

		// return nil will commit the whole transaction
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to set API events path ID: %v", err)
	}

	return nil
}

func getAPIUsageHitCountParamsToFilters(params operations.GetAPIUsageHitCountParams) *APIEventsFilters {
	return &APIEventsFilters{
		DestinationIPIsNot:    params.DestinationIPIsNot,
		DestinationIPIs:       params.DestinationIPIs,
		DestinationPortIsNot:  params.DestinationPortIsNot,
		DestinationPortIs:     params.DestinationPortIs,
		EndTime:               params.EndTime,
		ShowNonAPI:            params.ShowNonAPI,
		HasSpecDiffIs:         params.HasSpecDiffIs,
		SpecDiffTypeIs:        params.SpecDiffTypeIs,
		MethodIs:              params.MethodIs,
		ReconstructedPathIDIs: params.ReconstructedPathIDIs,
		ProvidedPathIDIs:      params.ProvidedPathIDIs,
		PathContains:          params.PathContains,
		PathEnd:               params.PathEnd,
		PathIsNot:             params.PathIsNot,
		PathIs:                params.PathIs,
		PathStart:             params.PathStart,
		SourceIPIsNot:         params.SourceIPIsNot,
		SourceIPIs:            params.SourceIPIs,
		SpecContains:          params.SpecContains,
		SpecEnd:               params.SpecEnd,
		SpecIsNot:             params.SpecIsNot,
		SpecIs:                params.SpecIs,
		SpecStart:             params.SpecStart,
		StartTime:             params.StartTime,
		StatusCodeGte:         params.StatusCodeGte,
		StatusCodeIsNot:       params.StatusCodeIsNot,
		StatusCodeIs:          params.StatusCodeIs,
		StatusCodeLte:         params.StatusCodeLte,
	}
}

func getAPIEventsParamsToFilters(params operations.GetAPIEventsParams) *APIEventsFilters {
	return &APIEventsFilters{
		DestinationIPIsNot:            params.DestinationIPIsNot,
		DestinationIPIs:               params.DestinationIPIs,
		DestinationPortIsNot:          params.DestinationPortIsNot,
		DestinationPortIs:             params.DestinationPortIs,
		EndTime:                       params.EndTime,
		ShowNonAPI:                    params.ShowNonAPI,
		HasSpecDiffIs:                 params.HasSpecDiffIs,
		SpecDiffTypeIs:                params.SpecDiffTypeIs,
		MethodIs:                      params.MethodIs,
		PathContains:                  params.PathContains,
		PathEnd:                       params.PathEnd,
		PathIsNot:                     params.PathIsNot,
		PathIs:                        params.PathIs,
		PathStart:                     params.PathStart,
		SourceIPIsNot:                 params.SourceIPIsNot,
		SourceIPIs:                    params.SourceIPIs,
		SpecContains:                  params.SpecContains,
		SpecEnd:                       params.SpecEnd,
		SpecIsNot:                     params.SpecIsNot,
		SpecIs:                        params.SpecIs,
		SpecStart:                     params.SpecStart,
		StartTime:                     params.StartTime,
		StatusCodeGte:                 params.StatusCodeGte,
		StatusCodeIsNot:               params.StatusCodeIsNot,
		StatusCodeIs:                  params.StatusCodeIs,
		StatusCodeLte:                 params.StatusCodeLte,
		DestinationK8sObjectNameIs:    params.DestinationK8sObjectNameIs,
		DestinationK8sObjectNameIsNot: params.DestinationK8sObjectNameIsNot,
		SourceK8sObjectNameIs:         params.SourceK8sObjectNameIs,
		SourceK8sObjectNameIsNot:      params.SourceK8sObjectNameIsNot,
	}
}
