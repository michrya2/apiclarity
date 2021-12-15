// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/apiclarity/apiclarity/api/server/models"
)

// GetAuthorizationModelNamespaceOKCode is the HTTP code returned for type GetAuthorizationModelNamespaceOK
const GetAuthorizationModelNamespaceOKCode int = 200

/*GetAuthorizationModelNamespaceOK Success

swagger:response getAuthorizationModelNamespaceOK
*/
type GetAuthorizationModelNamespaceOK struct {

	/*
	  In: Body
	*/
	Payload *models.AuthorizationModel `json:"body,omitempty"`
}

// NewGetAuthorizationModelNamespaceOK creates GetAuthorizationModelNamespaceOK with default headers values
func NewGetAuthorizationModelNamespaceOK() *GetAuthorizationModelNamespaceOK {

	return &GetAuthorizationModelNamespaceOK{}
}

// WithPayload adds the payload to the get authorization model namespace o k response
func (o *GetAuthorizationModelNamespaceOK) WithPayload(payload *models.AuthorizationModel) *GetAuthorizationModelNamespaceOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get authorization model namespace o k response
func (o *GetAuthorizationModelNamespaceOK) SetPayload(payload *models.AuthorizationModel) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetAuthorizationModelNamespaceOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

/*GetAuthorizationModelNamespaceDefault unknown error

swagger:response getAuthorizationModelNamespaceDefault
*/
type GetAuthorizationModelNamespaceDefault struct {
	_statusCode int

	/*
	  In: Body
	*/
	Payload *models.APIResponse `json:"body,omitempty"`
}

// NewGetAuthorizationModelNamespaceDefault creates GetAuthorizationModelNamespaceDefault with default headers values
func NewGetAuthorizationModelNamespaceDefault(code int) *GetAuthorizationModelNamespaceDefault {
	if code <= 0 {
		code = 500
	}

	return &GetAuthorizationModelNamespaceDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the get authorization model namespace default response
func (o *GetAuthorizationModelNamespaceDefault) WithStatusCode(code int) *GetAuthorizationModelNamespaceDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the get authorization model namespace default response
func (o *GetAuthorizationModelNamespaceDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WithPayload adds the payload to the get authorization model namespace default response
func (o *GetAuthorizationModelNamespaceDefault) WithPayload(payload *models.APIResponse) *GetAuthorizationModelNamespaceDefault {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get authorization model namespace default response
func (o *GetAuthorizationModelNamespaceDefault) SetPayload(payload *models.APIResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetAuthorizationModelNamespaceDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(o._statusCode)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}