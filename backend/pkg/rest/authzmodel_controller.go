package rest

import (
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/apiclarity/apiclarity/api/server/models"
	"github.com/apiclarity/apiclarity/api/server/restapi/operations"
	"github.com/go-openapi/runtime/middleware"
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

func (s *Server) PutAuthorizationModelTraceTraceIDApprove(params operations.PutAuthorizationModelTraceTraceIDApproveParams) middleware.Responder {
	err := s.bflaDetector.ApproveAPIEvent(params.HTTPRequest.Context(), uint32(params.TraceID))
	if err != nil {
		log.Error(err)
		return operations.NewPutAuthorizationModelTraceTraceIDApproveDefault(http.StatusInternalServerError).WithPayload(&models.APIResponse{
			Message: err.Error(),
		})
	}
	return operations.NewPutAuthorizationModelTraceTraceIDApproveOK().WithPayload(&models.SuccessResponse{Message: "Sent approve api event request successfully"})
}

func (s *Server) PutAuthorizationModelTraceTraceIDDeny(params operations.PutAuthorizationModelTraceTraceIDDenyParams) middleware.Responder {
	err := s.bflaDetector.DenyAPIEvent(params.HTTPRequest.Context(), uint32(params.TraceID))
	if err != nil {
		log.Error(err)
		return operations.NewPutAuthorizationModelTraceTraceIDDenyDefault(http.StatusInternalServerError).WithPayload(&models.APIResponse{
			Message: err.Error(),
		})
	}
	return operations.NewPutAuthorizationModelTraceTraceIDDenyOK().WithPayload(&models.SuccessResponse{Message: "Sent deny api event request successfully"})
}
