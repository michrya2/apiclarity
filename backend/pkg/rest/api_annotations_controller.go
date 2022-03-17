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

package rest

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
	log "github.com/sirupsen/logrus"

	"github.com/apiclarity/apiclarity/api/server/models"
	"github.com/apiclarity/apiclarity/api/server/restapi/operations"
)

func (s *Server) GetAPIAnnotationsAPIID(params operations.GetAPIAnnotationsAPIIDParams) middleware.Responder {

	apiAnnotationsFromDB, err := s.dbHandler.APIAnnotationsTable().GetAnnotations("", uint(params.APIID))

	if err != nil {
		log.Errorf("Failed to find api with id %v", params.APIID)
		return operations.NewGetAPIAnnotationsAPIIDDefault(http.StatusInternalServerError)
	}

	total := int64(len(apiAnnotationsFromDB))
	items := []*models.APIAnnotation{}

	for _, a := range apiAnnotationsFromDB {
		items = append(items, &models.APIAnnotation{
			Name:  a.Name,
			Model: string(a.Annotation), // XXX BASE64 it
		})
	}

	return operations.NewGetAPIAnnotationsAPIIDOK().WithPayload(&operations.GetAPIAnnotationsAPIIDOKBody{
		Items: items,
		Total: &total,
	})
}
