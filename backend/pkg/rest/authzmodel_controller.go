package rest

import (
	"fmt"
	"github.com/apiclarity/apiclarity/api/server/models"
	"github.com/apiclarity/apiclarity/api/server/restapi/operations"
	"github.com/go-openapi/runtime/middleware"
	log "github.com/sirupsen/logrus"
	"net/http"
)

func (s *Server) GetAuthorizationModelNamespace(params operations.GetAuthorizationModelNamespaceParams) middleware.Responder {
	am, err := s.authzmodelRepo.Load(params.HTTPRequest.Context(), params.Namespace)
	if err != nil {
		log.Error(err)
		return operations.NewGetAuthorizationModelNamespaceDefault(http.StatusInternalServerError).WithPayload(&models.APIResponse{
			Message: fmt.Sprintf("Unable to load authorization model namespace: %q", params.Namespace),
		})
	}

	return operations.NewGetAuthorizationModelNamespaceOK().WithPayload(am.ToModel())
}
