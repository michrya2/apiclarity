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
	"fmt"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/apiclarity/apiclarity/api/server/models"
	"github.com/apiclarity/apiclarity/api/server/restapi/operations"
)

const (
	apiInventoryTableName = "api_inventory"

	// NOTE: when changing one of the column names change also the gorm label in APIInfo.
	idColumnName                    = "id"
	typeColumnName                  = "type"
	nameColumnName                  = "name"
	portColumnName                  = "port"
	hasProvidedSpecColumnName       = "has_provided_spec"
	hasReconstructedSpecColumnName  = "has_reconstructed_spec"
	reconstructedSpecColumnName     = "reconstructed_spec"
	reconstructedSpecInfoColumnName = "reconstructed_spec_info"
	providedSpecColumnName          = "provided_spec"
	providedSpecInfoColumnName      = "provided_spec_info"
)

type APIInfo struct {
	// will be populated after inserting to DB
	ID uint `json:"id,omitempty" gorm:"primarykey" faker:"-"`

	Type                  models.APIType `json:"type,omitempty" gorm:"column:type" faker:"oneof: INTERNAL, EXTERNAL"`
	Name                  string         `json:"name,omitempty" gorm:"column:name" faker:"oneof: test.com, example.com, kaki.org"`
	Port                  int64          `json:"port,omitempty" gorm:"column:port" faker:"oneof: 80, 443"`
	HasProvidedSpec       bool           `json:"hasProvidedSpec,omitempty" gorm:"column:has_provided_spec"`
	HasReconstructedSpec  bool           `json:"hasReconstructedSpec,omitempty" gorm:"column:has_reconstructed_spec"`
	ReconstructedSpec     string         `json:"reconstructedSpec,omitempty" gorm:"column:reconstructed_spec" faker:"-"`
	ReconstructedSpecInfo string         `json:"reconstructedSpecInfo,omitempty" gorm:"column:reconstructed_spec_info" faker:"-"`
	ProvidedSpec          string         `json:"providedSpec,omitempty" gorm:"column:provided_spec" faker:"-"`
	ProvidedSpecInfo      string         `json:"providedSpecInfo,omitempty" gorm:"column:provided_spec_info" faker:"-"`
}

func (APIInfo) TableName() string {
	return apiInventoryTableName
}

func APIInfoFromDB(event *APIInfo) *models.APIInfo {
	return &models.APIInfo{
		HasProvidedSpec:      &event.HasProvidedSpec,
		HasReconstructedSpec: &event.HasReconstructedSpec,
		ID:                   uint32(event.ID),
		Name:                 event.Name,
		Port:                 event.Port,
	}
}

func GetAPIInventoryTable() *gorm.DB {
	return DB.Table(apiInventoryTableName)
}

func CreateAPIInfo(event *APIInfo) {
	if result := GetAPIInventoryTable().Create(event); result.Error != nil {
		log.Errorf("Failed to create api: %v", result.Error)
	} else {
		log.Infof("API created %+v", event)
	}
}

func GetAPIInventoryByName(name string) (*APIInfo, error) {
	apiInfo := &APIInfo{}
	tx := GetAPIInventoryTable()
	tx = FilterIs(tx, nameColumnName, []string{name})
	tx.First(apiInfo)
	if tx.Error != nil {
		return nil, tx.Error
	}
	return apiInfo, nil
}

func GetAPIInventoryAndTotal(params operations.GetAPIInventoryParams) ([]APIInfo, int64, error) {
	var apiInventory []APIInfo
	var count int64

	tx := setAPIInventoryFilters(GetAPIInventoryTable(), params)
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
		Find(&apiInventory).Error; err != nil {
		return nil, 0, err
	}

	return apiInventory, count, nil
}

func setAPIInventoryFilters(table *gorm.DB, params operations.GetAPIInventoryParams) *gorm.DB {
	// type filter
	table = FilterIs(table, typeColumnName, []string{params.Type})

	// id filter
	if params.APIID != nil {
		table = FilterIs(table, idColumnName, []string{*params.APIID})
	}

	// names filter
	table = FilterIs(table, nameColumnName, params.NameIs)
	table = FilterIsNot(table, nameColumnName, params.NameIsNot)
	table = FilterContains(table, nameColumnName, params.NameContains)
	table = FilterStartsWith(table, nameColumnName, params.NameStart)
	table = FilterEndsWith(table, nameColumnName, params.NameEnd)

	// ports filters
	table = FilterIs(table, portColumnName, params.PortIs)
	table = FilterIsNot(table, portColumnName, params.PortIsNot)

	// has provided spec diff filter
	table = FilterIsBool(table, hasProvidedSpecColumnName, params.HasProvidedSpecIs)

	// has reconstructed spec diff filter
	table = FilterIsBool(table, hasReconstructedSpecColumnName, params.HasReconstructedSpecIs)

	return table
}

func GetAPIID(name, port string) (uint, error) {
	apiInfo := APIInfo{}
	if result := GetAPIInventoryTable().Where(nameColumnName+" = ?", name).Where(portColumnName+" = ?", port).First(&apiInfo); result.Error != nil {
		return 0, result.Error
	}

	return apiInfo.ID, nil
}
