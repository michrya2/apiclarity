// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// NewDeleteControlGatewaysGatewayIDParams creates a new DeleteControlGatewaysGatewayIDParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteControlGatewaysGatewayIDParams() *DeleteControlGatewaysGatewayIDParams {
	return &DeleteControlGatewaysGatewayIDParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteControlGatewaysGatewayIDParamsWithTimeout creates a new DeleteControlGatewaysGatewayIDParams object
// with the ability to set a timeout on a request.
func NewDeleteControlGatewaysGatewayIDParamsWithTimeout(timeout time.Duration) *DeleteControlGatewaysGatewayIDParams {
	return &DeleteControlGatewaysGatewayIDParams{
		timeout: timeout,
	}
}

// NewDeleteControlGatewaysGatewayIDParamsWithContext creates a new DeleteControlGatewaysGatewayIDParams object
// with the ability to set a context for a request.
func NewDeleteControlGatewaysGatewayIDParamsWithContext(ctx context.Context) *DeleteControlGatewaysGatewayIDParams {
	return &DeleteControlGatewaysGatewayIDParams{
		Context: ctx,
	}
}

// NewDeleteControlGatewaysGatewayIDParamsWithHTTPClient creates a new DeleteControlGatewaysGatewayIDParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteControlGatewaysGatewayIDParamsWithHTTPClient(client *http.Client) *DeleteControlGatewaysGatewayIDParams {
	return &DeleteControlGatewaysGatewayIDParams{
		HTTPClient: client,
	}
}

/* DeleteControlGatewaysGatewayIDParams contains all the parameters to send to the API endpoint
   for the delete control gateways gateway ID operation.

   Typically these are written to a http.Request.
*/
type DeleteControlGatewaysGatewayIDParams struct {

	/* GatewayID.

	   Gateway ID
	*/
	GatewayID int64

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete control gateways gateway ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteControlGatewaysGatewayIDParams) WithDefaults() *DeleteControlGatewaysGatewayIDParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete control gateways gateway ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteControlGatewaysGatewayIDParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the delete control gateways gateway ID params
func (o *DeleteControlGatewaysGatewayIDParams) WithTimeout(timeout time.Duration) *DeleteControlGatewaysGatewayIDParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete control gateways gateway ID params
func (o *DeleteControlGatewaysGatewayIDParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete control gateways gateway ID params
func (o *DeleteControlGatewaysGatewayIDParams) WithContext(ctx context.Context) *DeleteControlGatewaysGatewayIDParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete control gateways gateway ID params
func (o *DeleteControlGatewaysGatewayIDParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete control gateways gateway ID params
func (o *DeleteControlGatewaysGatewayIDParams) WithHTTPClient(client *http.Client) *DeleteControlGatewaysGatewayIDParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete control gateways gateway ID params
func (o *DeleteControlGatewaysGatewayIDParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithGatewayID adds the gatewayID to the delete control gateways gateway ID params
func (o *DeleteControlGatewaysGatewayIDParams) WithGatewayID(gatewayID int64) *DeleteControlGatewaysGatewayIDParams {
	o.SetGatewayID(gatewayID)
	return o
}

// SetGatewayID adds the gatewayId to the delete control gateways gateway ID params
func (o *DeleteControlGatewaysGatewayIDParams) SetGatewayID(gatewayID int64) {
	o.GatewayID = gatewayID
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteControlGatewaysGatewayIDParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param gatewayId
	if err := r.SetPathParam("gatewayId", swag.FormatInt64(o.GatewayID)); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}