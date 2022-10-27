// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/loads"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/runtime/security"
	"github.com/go-openapi/spec"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// NewAPIClarityAPIsAPI creates a new APIClarityAPIs instance
func NewAPIClarityAPIsAPI(spec *loads.Document) *APIClarityAPIsAPI {
	return &APIClarityAPIsAPI{
		handlers:            make(map[string]map[string]http.Handler),
		formats:             strfmt.Default,
		defaultConsumes:     "application/json",
		defaultProduces:     "application/json",
		customConsumers:     make(map[string]runtime.Consumer),
		customProducers:     make(map[string]runtime.Producer),
		PreServerShutdown:   func() {},
		ServerShutdown:      func() {},
		spec:                spec,
		useSwaggerUI:        false,
		ServeError:          errors.ServeError,
		BasicAuthenticator:  security.BasicAuth,
		APIKeyAuthenticator: security.APIKeyAuth,
		BearerAuthenticator: security.BearerAuth,

		JSONConsumer: runtime.JSONConsumer(),

		JSONProducer: runtime.JSONProducer(),

		DeleteAPIInventoryAPIIDSpecsProvidedSpecHandler: DeleteAPIInventoryAPIIDSpecsProvidedSpecHandlerFunc(func(params DeleteAPIInventoryAPIIDSpecsProvidedSpecParams) middleware.Responder {
			return middleware.NotImplemented("operation DeleteAPIInventoryAPIIDSpecsProvidedSpec has not yet been implemented")
		}),
		DeleteAPIInventoryAPIIDSpecsReconstructedSpecHandler: DeleteAPIInventoryAPIIDSpecsReconstructedSpecHandlerFunc(func(params DeleteAPIInventoryAPIIDSpecsReconstructedSpecParams) middleware.Responder {
			return middleware.NotImplemented("operation DeleteAPIInventoryAPIIDSpecsReconstructedSpec has not yet been implemented")
		}),
		DeleteControlGatewaysGatewayIDHandler: DeleteControlGatewaysGatewayIDHandlerFunc(func(params DeleteControlGatewaysGatewayIDParams) middleware.Responder {
			return middleware.NotImplemented("operation DeleteControlGatewaysGatewayID has not yet been implemented")
		}),
		GetAPIEventsHandler: GetAPIEventsHandlerFunc(func(params GetAPIEventsParams) middleware.Responder {
			return middleware.NotImplemented("operation GetAPIEvents has not yet been implemented")
		}),
		GetAPIEventsEventIDHandler: GetAPIEventsEventIDHandlerFunc(func(params GetAPIEventsEventIDParams) middleware.Responder {
			return middleware.NotImplemented("operation GetAPIEventsEventID has not yet been implemented")
		}),
		GetAPIEventsEventIDProvidedSpecDiffHandler: GetAPIEventsEventIDProvidedSpecDiffHandlerFunc(func(params GetAPIEventsEventIDProvidedSpecDiffParams) middleware.Responder {
			return middleware.NotImplemented("operation GetAPIEventsEventIDProvidedSpecDiff has not yet been implemented")
		}),
		GetAPIEventsEventIDReconstructedSpecDiffHandler: GetAPIEventsEventIDReconstructedSpecDiffHandlerFunc(func(params GetAPIEventsEventIDReconstructedSpecDiffParams) middleware.Responder {
			return middleware.NotImplemented("operation GetAPIEventsEventIDReconstructedSpecDiff has not yet been implemented")
		}),
		GetAPIInventoryHandler: GetAPIInventoryHandlerFunc(func(params GetAPIInventoryParams) middleware.Responder {
			return middleware.NotImplemented("operation GetAPIInventory has not yet been implemented")
		}),
		GetAPIInventoryAPIIDAPIInfoHandler: GetAPIInventoryAPIIDAPIInfoHandlerFunc(func(params GetAPIInventoryAPIIDAPIInfoParams) middleware.Responder {
			return middleware.NotImplemented("operation GetAPIInventoryAPIIDAPIInfo has not yet been implemented")
		}),
		GetAPIInventoryAPIIDFromHostAndPortHandler: GetAPIInventoryAPIIDFromHostAndPortHandlerFunc(func(params GetAPIInventoryAPIIDFromHostAndPortParams) middleware.Responder {
			return middleware.NotImplemented("operation GetAPIInventoryAPIIDFromHostAndPort has not yet been implemented")
		}),
		GetAPIInventoryAPIIDProvidedSwaggerJSONHandler: GetAPIInventoryAPIIDProvidedSwaggerJSONHandlerFunc(func(params GetAPIInventoryAPIIDProvidedSwaggerJSONParams) middleware.Responder {
			return middleware.NotImplemented("operation GetAPIInventoryAPIIDProvidedSwaggerJSON has not yet been implemented")
		}),
		GetAPIInventoryAPIIDReconstructedSwaggerJSONHandler: GetAPIInventoryAPIIDReconstructedSwaggerJSONHandlerFunc(func(params GetAPIInventoryAPIIDReconstructedSwaggerJSONParams) middleware.Responder {
			return middleware.NotImplemented("operation GetAPIInventoryAPIIDReconstructedSwaggerJSON has not yet been implemented")
		}),
		GetAPIInventoryAPIIDSpecsHandler: GetAPIInventoryAPIIDSpecsHandlerFunc(func(params GetAPIInventoryAPIIDSpecsParams) middleware.Responder {
			return middleware.NotImplemented("operation GetAPIInventoryAPIIDSpecs has not yet been implemented")
		}),
		GetAPIInventoryAPIIDSuggestedReviewHandler: GetAPIInventoryAPIIDSuggestedReviewHandlerFunc(func(params GetAPIInventoryAPIIDSuggestedReviewParams) middleware.Responder {
			return middleware.NotImplemented("operation GetAPIInventoryAPIIDSuggestedReview has not yet been implemented")
		}),
		GetAPIUsageHitCountHandler: GetAPIUsageHitCountHandlerFunc(func(params GetAPIUsageHitCountParams) middleware.Responder {
			return middleware.NotImplemented("operation GetAPIUsageHitCount has not yet been implemented")
		}),
		GetControlGatewaysHandler: GetControlGatewaysHandlerFunc(func(params GetControlGatewaysParams) middleware.Responder {
			return middleware.NotImplemented("operation GetControlGateways has not yet been implemented")
		}),
		GetControlGatewaysGatewayIDHandler: GetControlGatewaysGatewayIDHandlerFunc(func(params GetControlGatewaysGatewayIDParams) middleware.Responder {
			return middleware.NotImplemented("operation GetControlGatewaysGatewayID has not yet been implemented")
		}),
		GetDashboardAPIUsageHandler: GetDashboardAPIUsageHandlerFunc(func(params GetDashboardAPIUsageParams) middleware.Responder {
			return middleware.NotImplemented("operation GetDashboardAPIUsage has not yet been implemented")
		}),
		GetDashboardAPIUsageLatestDiffsHandler: GetDashboardAPIUsageLatestDiffsHandlerFunc(func(params GetDashboardAPIUsageLatestDiffsParams) middleware.Responder {
			return middleware.NotImplemented("operation GetDashboardAPIUsageLatestDiffs has not yet been implemented")
		}),
		GetDashboardAPIUsageMostUsedHandler: GetDashboardAPIUsageMostUsedHandlerFunc(func(params GetDashboardAPIUsageMostUsedParams) middleware.Responder {
			return middleware.NotImplemented("operation GetDashboardAPIUsageMostUsed has not yet been implemented")
		}),
		GetFeaturesHandler: GetFeaturesHandlerFunc(func(params GetFeaturesParams) middleware.Responder {
			return middleware.NotImplemented("operation GetFeatures has not yet been implemented")
		}),
		PostAPIInventoryHandler: PostAPIInventoryHandlerFunc(func(params PostAPIInventoryParams) middleware.Responder {
			return middleware.NotImplemented("operation PostAPIInventory has not yet been implemented")
		}),
		PostAPIInventoryReviewIDApprovedReviewHandler: PostAPIInventoryReviewIDApprovedReviewHandlerFunc(func(params PostAPIInventoryReviewIDApprovedReviewParams) middleware.Responder {
			return middleware.NotImplemented("operation PostAPIInventoryReviewIDApprovedReview has not yet been implemented")
		}),
		PostControlGatewaysHandler: PostControlGatewaysHandlerFunc(func(params PostControlGatewaysParams) middleware.Responder {
			return middleware.NotImplemented("operation PostControlGateways has not yet been implemented")
		}),
		PostControlNewDiscoveredAPIsHandler: PostControlNewDiscoveredAPIsHandlerFunc(func(params PostControlNewDiscoveredAPIsParams) middleware.Responder {
			return middleware.NotImplemented("operation PostControlNewDiscoveredAPIs has not yet been implemented")
		}),
		PutAPIInventoryAPIIDSpecsProvidedSpecHandler: PutAPIInventoryAPIIDSpecsProvidedSpecHandlerFunc(func(params PutAPIInventoryAPIIDSpecsProvidedSpecParams) middleware.Responder {
			return middleware.NotImplemented("operation PutAPIInventoryAPIIDSpecsProvidedSpec has not yet been implemented")
		}),
	}
}

/*APIClarityAPIsAPI the API clarity a p is API */
type APIClarityAPIsAPI struct {
	spec            *loads.Document
	context         *middleware.Context
	handlers        map[string]map[string]http.Handler
	formats         strfmt.Registry
	customConsumers map[string]runtime.Consumer
	customProducers map[string]runtime.Producer
	defaultConsumes string
	defaultProduces string
	Middleware      func(middleware.Builder) http.Handler
	useSwaggerUI    bool

	// BasicAuthenticator generates a runtime.Authenticator from the supplied basic auth function.
	// It has a default implementation in the security package, however you can replace it for your particular usage.
	BasicAuthenticator func(security.UserPassAuthentication) runtime.Authenticator

	// APIKeyAuthenticator generates a runtime.Authenticator from the supplied token auth function.
	// It has a default implementation in the security package, however you can replace it for your particular usage.
	APIKeyAuthenticator func(string, string, security.TokenAuthentication) runtime.Authenticator

	// BearerAuthenticator generates a runtime.Authenticator from the supplied bearer token auth function.
	// It has a default implementation in the security package, however you can replace it for your particular usage.
	BearerAuthenticator func(string, security.ScopedTokenAuthentication) runtime.Authenticator

	// JSONConsumer registers a consumer for the following mime types:
	//   - application/json
	JSONConsumer runtime.Consumer

	// JSONProducer registers a producer for the following mime types:
	//   - application/json
	JSONProducer runtime.Producer

	// DeleteAPIInventoryAPIIDSpecsProvidedSpecHandler sets the operation handler for the delete API inventory API ID specs provided spec operation
	DeleteAPIInventoryAPIIDSpecsProvidedSpecHandler DeleteAPIInventoryAPIIDSpecsProvidedSpecHandler
	// DeleteAPIInventoryAPIIDSpecsReconstructedSpecHandler sets the operation handler for the delete API inventory API ID specs reconstructed spec operation
	DeleteAPIInventoryAPIIDSpecsReconstructedSpecHandler DeleteAPIInventoryAPIIDSpecsReconstructedSpecHandler
	// DeleteControlGatewaysGatewayIDHandler sets the operation handler for the delete control gateways gateway ID operation
	DeleteControlGatewaysGatewayIDHandler DeleteControlGatewaysGatewayIDHandler
	// GetAPIEventsHandler sets the operation handler for the get API events operation
	GetAPIEventsHandler GetAPIEventsHandler
	// GetAPIEventsEventIDHandler sets the operation handler for the get API events event ID operation
	GetAPIEventsEventIDHandler GetAPIEventsEventIDHandler
	// GetAPIEventsEventIDProvidedSpecDiffHandler sets the operation handler for the get API events event ID provided spec diff operation
	GetAPIEventsEventIDProvidedSpecDiffHandler GetAPIEventsEventIDProvidedSpecDiffHandler
	// GetAPIEventsEventIDReconstructedSpecDiffHandler sets the operation handler for the get API events event ID reconstructed spec diff operation
	GetAPIEventsEventIDReconstructedSpecDiffHandler GetAPIEventsEventIDReconstructedSpecDiffHandler
	// GetAPIInventoryHandler sets the operation handler for the get API inventory operation
	GetAPIInventoryHandler GetAPIInventoryHandler
	// GetAPIInventoryAPIIDAPIInfoHandler sets the operation handler for the get API inventory API ID API info operation
	GetAPIInventoryAPIIDAPIInfoHandler GetAPIInventoryAPIIDAPIInfoHandler
	// GetAPIInventoryAPIIDFromHostAndPortHandler sets the operation handler for the get API inventory API ID from host and port operation
	GetAPIInventoryAPIIDFromHostAndPortHandler GetAPIInventoryAPIIDFromHostAndPortHandler
	// GetAPIInventoryAPIIDProvidedSwaggerJSONHandler sets the operation handler for the get API inventory API ID provided swagger JSON operation
	GetAPIInventoryAPIIDProvidedSwaggerJSONHandler GetAPIInventoryAPIIDProvidedSwaggerJSONHandler
	// GetAPIInventoryAPIIDReconstructedSwaggerJSONHandler sets the operation handler for the get API inventory API ID reconstructed swagger JSON operation
	GetAPIInventoryAPIIDReconstructedSwaggerJSONHandler GetAPIInventoryAPIIDReconstructedSwaggerJSONHandler
	// GetAPIInventoryAPIIDSpecsHandler sets the operation handler for the get API inventory API ID specs operation
	GetAPIInventoryAPIIDSpecsHandler GetAPIInventoryAPIIDSpecsHandler
	// GetAPIInventoryAPIIDSuggestedReviewHandler sets the operation handler for the get API inventory API ID suggested review operation
	GetAPIInventoryAPIIDSuggestedReviewHandler GetAPIInventoryAPIIDSuggestedReviewHandler
	// GetAPIUsageHitCountHandler sets the operation handler for the get API usage hit count operation
	GetAPIUsageHitCountHandler GetAPIUsageHitCountHandler
	// GetControlGatewaysHandler sets the operation handler for the get control gateways operation
	GetControlGatewaysHandler GetControlGatewaysHandler
	// GetControlGatewaysGatewayIDHandler sets the operation handler for the get control gateways gateway ID operation
	GetControlGatewaysGatewayIDHandler GetControlGatewaysGatewayIDHandler
	// GetDashboardAPIUsageHandler sets the operation handler for the get dashboard API usage operation
	GetDashboardAPIUsageHandler GetDashboardAPIUsageHandler
	// GetDashboardAPIUsageLatestDiffsHandler sets the operation handler for the get dashboard API usage latest diffs operation
	GetDashboardAPIUsageLatestDiffsHandler GetDashboardAPIUsageLatestDiffsHandler
	// GetDashboardAPIUsageMostUsedHandler sets the operation handler for the get dashboard API usage most used operation
	GetDashboardAPIUsageMostUsedHandler GetDashboardAPIUsageMostUsedHandler
	// GetFeaturesHandler sets the operation handler for the get features operation
	GetFeaturesHandler GetFeaturesHandler
	// PostAPIInventoryHandler sets the operation handler for the post API inventory operation
	PostAPIInventoryHandler PostAPIInventoryHandler
	// PostAPIInventoryReviewIDApprovedReviewHandler sets the operation handler for the post API inventory review ID approved review operation
	PostAPIInventoryReviewIDApprovedReviewHandler PostAPIInventoryReviewIDApprovedReviewHandler
	// PostControlGatewaysHandler sets the operation handler for the post control gateways operation
	PostControlGatewaysHandler PostControlGatewaysHandler
	// PostControlNewDiscoveredAPIsHandler sets the operation handler for the post control new discovered a p is operation
	PostControlNewDiscoveredAPIsHandler PostControlNewDiscoveredAPIsHandler
	// PutAPIInventoryAPIIDSpecsProvidedSpecHandler sets the operation handler for the put API inventory API ID specs provided spec operation
	PutAPIInventoryAPIIDSpecsProvidedSpecHandler PutAPIInventoryAPIIDSpecsProvidedSpecHandler

	// ServeError is called when an error is received, there is a default handler
	// but you can set your own with this
	ServeError func(http.ResponseWriter, *http.Request, error)

	// PreServerShutdown is called before the HTTP(S) server is shutdown
	// This allows for custom functions to get executed before the HTTP(S) server stops accepting traffic
	PreServerShutdown func()

	// ServerShutdown is called when the HTTP(S) server is shut down and done
	// handling all active connections and does not accept connections any more
	ServerShutdown func()

	// Custom command line argument groups with their descriptions
	CommandLineOptionsGroups []swag.CommandLineOptionsGroup

	// User defined logger function.
	Logger func(string, ...interface{})
}

// UseRedoc for documentation at /docs
func (o *APIClarityAPIsAPI) UseRedoc() {
	o.useSwaggerUI = false
}

// UseSwaggerUI for documentation at /docs
func (o *APIClarityAPIsAPI) UseSwaggerUI() {
	o.useSwaggerUI = true
}

// SetDefaultProduces sets the default produces media type
func (o *APIClarityAPIsAPI) SetDefaultProduces(mediaType string) {
	o.defaultProduces = mediaType
}

// SetDefaultConsumes returns the default consumes media type
func (o *APIClarityAPIsAPI) SetDefaultConsumes(mediaType string) {
	o.defaultConsumes = mediaType
}

// SetSpec sets a spec that will be served for the clients.
func (o *APIClarityAPIsAPI) SetSpec(spec *loads.Document) {
	o.spec = spec
}

// DefaultProduces returns the default produces media type
func (o *APIClarityAPIsAPI) DefaultProduces() string {
	return o.defaultProduces
}

// DefaultConsumes returns the default consumes media type
func (o *APIClarityAPIsAPI) DefaultConsumes() string {
	return o.defaultConsumes
}

// Formats returns the registered string formats
func (o *APIClarityAPIsAPI) Formats() strfmt.Registry {
	return o.formats
}

// RegisterFormat registers a custom format validator
func (o *APIClarityAPIsAPI) RegisterFormat(name string, format strfmt.Format, validator strfmt.Validator) {
	o.formats.Add(name, format, validator)
}

// Validate validates the registrations in the APIClarityAPIsAPI
func (o *APIClarityAPIsAPI) Validate() error {
	var unregistered []string

	if o.JSONConsumer == nil {
		unregistered = append(unregistered, "JSONConsumer")
	}

	if o.JSONProducer == nil {
		unregistered = append(unregistered, "JSONProducer")
	}

	if o.DeleteAPIInventoryAPIIDSpecsProvidedSpecHandler == nil {
		unregistered = append(unregistered, "DeleteAPIInventoryAPIIDSpecsProvidedSpecHandler")
	}
	if o.DeleteAPIInventoryAPIIDSpecsReconstructedSpecHandler == nil {
		unregistered = append(unregistered, "DeleteAPIInventoryAPIIDSpecsReconstructedSpecHandler")
	}
	if o.DeleteControlGatewaysGatewayIDHandler == nil {
		unregistered = append(unregistered, "DeleteControlGatewaysGatewayIDHandler")
	}
	if o.GetAPIEventsHandler == nil {
		unregistered = append(unregistered, "GetAPIEventsHandler")
	}
	if o.GetAPIEventsEventIDHandler == nil {
		unregistered = append(unregistered, "GetAPIEventsEventIDHandler")
	}
	if o.GetAPIEventsEventIDProvidedSpecDiffHandler == nil {
		unregistered = append(unregistered, "GetAPIEventsEventIDProvidedSpecDiffHandler")
	}
	if o.GetAPIEventsEventIDReconstructedSpecDiffHandler == nil {
		unregistered = append(unregistered, "GetAPIEventsEventIDReconstructedSpecDiffHandler")
	}
	if o.GetAPIInventoryHandler == nil {
		unregistered = append(unregistered, "GetAPIInventoryHandler")
	}
	if o.GetAPIInventoryAPIIDAPIInfoHandler == nil {
		unregistered = append(unregistered, "GetAPIInventoryAPIIDAPIInfoHandler")
	}
	if o.GetAPIInventoryAPIIDFromHostAndPortHandler == nil {
		unregistered = append(unregistered, "GetAPIInventoryAPIIDFromHostAndPortHandler")
	}
	if o.GetAPIInventoryAPIIDProvidedSwaggerJSONHandler == nil {
		unregistered = append(unregistered, "GetAPIInventoryAPIIDProvidedSwaggerJSONHandler")
	}
	if o.GetAPIInventoryAPIIDReconstructedSwaggerJSONHandler == nil {
		unregistered = append(unregistered, "GetAPIInventoryAPIIDReconstructedSwaggerJSONHandler")
	}
	if o.GetAPIInventoryAPIIDSpecsHandler == nil {
		unregistered = append(unregistered, "GetAPIInventoryAPIIDSpecsHandler")
	}
	if o.GetAPIInventoryAPIIDSuggestedReviewHandler == nil {
		unregistered = append(unregistered, "GetAPIInventoryAPIIDSuggestedReviewHandler")
	}
	if o.GetAPIUsageHitCountHandler == nil {
		unregistered = append(unregistered, "GetAPIUsageHitCountHandler")
	}
	if o.GetControlGatewaysHandler == nil {
		unregistered = append(unregistered, "GetControlGatewaysHandler")
	}
	if o.GetControlGatewaysGatewayIDHandler == nil {
		unregistered = append(unregistered, "GetControlGatewaysGatewayIDHandler")
	}
	if o.GetDashboardAPIUsageHandler == nil {
		unregistered = append(unregistered, "GetDashboardAPIUsageHandler")
	}
	if o.GetDashboardAPIUsageLatestDiffsHandler == nil {
		unregistered = append(unregistered, "GetDashboardAPIUsageLatestDiffsHandler")
	}
	if o.GetDashboardAPIUsageMostUsedHandler == nil {
		unregistered = append(unregistered, "GetDashboardAPIUsageMostUsedHandler")
	}
	if o.GetFeaturesHandler == nil {
		unregistered = append(unregistered, "GetFeaturesHandler")
	}
	if o.PostAPIInventoryHandler == nil {
		unregistered = append(unregistered, "PostAPIInventoryHandler")
	}
	if o.PostAPIInventoryReviewIDApprovedReviewHandler == nil {
		unregistered = append(unregistered, "PostAPIInventoryReviewIDApprovedReviewHandler")
	}
	if o.PostControlGatewaysHandler == nil {
		unregistered = append(unregistered, "PostControlGatewaysHandler")
	}
	if o.PostControlNewDiscoveredAPIsHandler == nil {
		unregistered = append(unregistered, "PostControlNewDiscoveredAPIsHandler")
	}
	if o.PutAPIInventoryAPIIDSpecsProvidedSpecHandler == nil {
		unregistered = append(unregistered, "PutAPIInventoryAPIIDSpecsProvidedSpecHandler")
	}

	if len(unregistered) > 0 {
		return fmt.Errorf("missing registration: %s", strings.Join(unregistered, ", "))
	}

	return nil
}

// ServeErrorFor gets a error handler for a given operation id
func (o *APIClarityAPIsAPI) ServeErrorFor(operationID string) func(http.ResponseWriter, *http.Request, error) {
	return o.ServeError
}

// AuthenticatorsFor gets the authenticators for the specified security schemes
func (o *APIClarityAPIsAPI) AuthenticatorsFor(schemes map[string]spec.SecurityScheme) map[string]runtime.Authenticator {
	return nil
}

// Authorizer returns the registered authorizer
func (o *APIClarityAPIsAPI) Authorizer() runtime.Authorizer {
	return nil
}

// ConsumersFor gets the consumers for the specified media types.
// MIME type parameters are ignored here.
func (o *APIClarityAPIsAPI) ConsumersFor(mediaTypes []string) map[string]runtime.Consumer {
	result := make(map[string]runtime.Consumer, len(mediaTypes))
	for _, mt := range mediaTypes {
		switch mt {
		case "application/json":
			result["application/json"] = o.JSONConsumer
		}

		if c, ok := o.customConsumers[mt]; ok {
			result[mt] = c
		}
	}
	return result
}

// ProducersFor gets the producers for the specified media types.
// MIME type parameters are ignored here.
func (o *APIClarityAPIsAPI) ProducersFor(mediaTypes []string) map[string]runtime.Producer {
	result := make(map[string]runtime.Producer, len(mediaTypes))
	for _, mt := range mediaTypes {
		switch mt {
		case "application/json":
			result["application/json"] = o.JSONProducer
		}

		if p, ok := o.customProducers[mt]; ok {
			result[mt] = p
		}
	}
	return result
}

// HandlerFor gets a http.Handler for the provided operation method and path
func (o *APIClarityAPIsAPI) HandlerFor(method, path string) (http.Handler, bool) {
	if o.handlers == nil {
		return nil, false
	}
	um := strings.ToUpper(method)
	if _, ok := o.handlers[um]; !ok {
		return nil, false
	}
	if path == "/" {
		path = ""
	}
	h, ok := o.handlers[um][path]
	return h, ok
}

// Context returns the middleware context for the API clarity a p is API
func (o *APIClarityAPIsAPI) Context() *middleware.Context {
	if o.context == nil {
		o.context = middleware.NewRoutableContext(o.spec, o, nil)
	}

	return o.context
}

func (o *APIClarityAPIsAPI) initHandlerCache() {
	o.Context() // don't care about the result, just that the initialization happened
	if o.handlers == nil {
		o.handlers = make(map[string]map[string]http.Handler)
	}

	if o.handlers["DELETE"] == nil {
		o.handlers["DELETE"] = make(map[string]http.Handler)
	}
	o.handlers["DELETE"]["/apiInventory/{apiId}/specs/providedSpec"] = NewDeleteAPIInventoryAPIIDSpecsProvidedSpec(o.context, o.DeleteAPIInventoryAPIIDSpecsProvidedSpecHandler)
	if o.handlers["DELETE"] == nil {
		o.handlers["DELETE"] = make(map[string]http.Handler)
	}
	o.handlers["DELETE"]["/apiInventory/{apiId}/specs/reconstructedSpec"] = NewDeleteAPIInventoryAPIIDSpecsReconstructedSpec(o.context, o.DeleteAPIInventoryAPIIDSpecsReconstructedSpecHandler)
	if o.handlers["DELETE"] == nil {
		o.handlers["DELETE"] = make(map[string]http.Handler)
	}
	o.handlers["DELETE"]["/control/gateways/{gatewayId}"] = NewDeleteControlGatewaysGatewayID(o.context, o.DeleteControlGatewaysGatewayIDHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/apiEvents"] = NewGetAPIEvents(o.context, o.GetAPIEventsHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/apiEvents/{eventId}"] = NewGetAPIEventsEventID(o.context, o.GetAPIEventsEventIDHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/apiEvents/{eventId}/providedSpecDiff"] = NewGetAPIEventsEventIDProvidedSpecDiff(o.context, o.GetAPIEventsEventIDProvidedSpecDiffHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/apiEvents/{eventId}/reconstructedSpecDiff"] = NewGetAPIEventsEventIDReconstructedSpecDiff(o.context, o.GetAPIEventsEventIDReconstructedSpecDiffHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/apiInventory"] = NewGetAPIInventory(o.context, o.GetAPIInventoryHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/apiInventory/{apiId}/apiInfo"] = NewGetAPIInventoryAPIIDAPIInfo(o.context, o.GetAPIInventoryAPIIDAPIInfoHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/apiInventory/apiId/fromHostAndPort"] = NewGetAPIInventoryAPIIDFromHostAndPort(o.context, o.GetAPIInventoryAPIIDFromHostAndPortHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/apiInventory/{apiId}/provided_swagger.json"] = NewGetAPIInventoryAPIIDProvidedSwaggerJSON(o.context, o.GetAPIInventoryAPIIDProvidedSwaggerJSONHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/apiInventory/{apiId}/reconstructed_swagger.json"] = NewGetAPIInventoryAPIIDReconstructedSwaggerJSON(o.context, o.GetAPIInventoryAPIIDReconstructedSwaggerJSONHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/apiInventory/{apiId}/specs"] = NewGetAPIInventoryAPIIDSpecs(o.context, o.GetAPIInventoryAPIIDSpecsHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/apiInventory/{apiId}/suggestedReview"] = NewGetAPIInventoryAPIIDSuggestedReview(o.context, o.GetAPIInventoryAPIIDSuggestedReviewHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/apiUsage/hitCount"] = NewGetAPIUsageHitCount(o.context, o.GetAPIUsageHitCountHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/control/gateways"] = NewGetControlGateways(o.context, o.GetControlGatewaysHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/control/gateways/{gatewayId}"] = NewGetControlGatewaysGatewayID(o.context, o.GetControlGatewaysGatewayIDHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/dashboard/apiUsage"] = NewGetDashboardAPIUsage(o.context, o.GetDashboardAPIUsageHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/dashboard/apiUsage/latestDiffs"] = NewGetDashboardAPIUsageLatestDiffs(o.context, o.GetDashboardAPIUsageLatestDiffsHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/dashboard/apiUsage/mostUsed"] = NewGetDashboardAPIUsageMostUsed(o.context, o.GetDashboardAPIUsageMostUsedHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/features"] = NewGetFeatures(o.context, o.GetFeaturesHandler)
	if o.handlers["POST"] == nil {
		o.handlers["POST"] = make(map[string]http.Handler)
	}
	o.handlers["POST"]["/apiInventory"] = NewPostAPIInventory(o.context, o.PostAPIInventoryHandler)
	if o.handlers["POST"] == nil {
		o.handlers["POST"] = make(map[string]http.Handler)
	}
	o.handlers["POST"]["/apiInventory/{reviewId}/approvedReview"] = NewPostAPIInventoryReviewIDApprovedReview(o.context, o.PostAPIInventoryReviewIDApprovedReviewHandler)
	if o.handlers["POST"] == nil {
		o.handlers["POST"] = make(map[string]http.Handler)
	}
	o.handlers["POST"]["/control/gateways"] = NewPostControlGateways(o.context, o.PostControlGatewaysHandler)
	if o.handlers["POST"] == nil {
		o.handlers["POST"] = make(map[string]http.Handler)
	}
	o.handlers["POST"]["/control/newDiscoveredAPIs"] = NewPostControlNewDiscoveredAPIs(o.context, o.PostControlNewDiscoveredAPIsHandler)
	if o.handlers["PUT"] == nil {
		o.handlers["PUT"] = make(map[string]http.Handler)
	}
	o.handlers["PUT"]["/apiInventory/{apiId}/specs/providedSpec"] = NewPutAPIInventoryAPIIDSpecsProvidedSpec(o.context, o.PutAPIInventoryAPIIDSpecsProvidedSpecHandler)
}

// Serve creates a http handler to serve the API over HTTP
// can be used directly in http.ListenAndServe(":8000", api.Serve(nil))
func (o *APIClarityAPIsAPI) Serve(builder middleware.Builder) http.Handler {
	o.Init()

	if o.Middleware != nil {
		return o.Middleware(builder)
	}
	if o.useSwaggerUI {
		return o.context.APIHandlerSwaggerUI(builder)
	}
	return o.context.APIHandler(builder)
}

// Init allows you to just initialize the handler cache, you can then recompose the middleware as you see fit
func (o *APIClarityAPIsAPI) Init() {
	if len(o.handlers) == 0 {
		o.initHandlerCache()
	}
}

// RegisterConsumer allows you to add (or override) a consumer for a media type.
func (o *APIClarityAPIsAPI) RegisterConsumer(mediaType string, consumer runtime.Consumer) {
	o.customConsumers[mediaType] = consumer
}

// RegisterProducer allows you to add (or override) a producer for a media type.
func (o *APIClarityAPIsAPI) RegisterProducer(mediaType string, producer runtime.Producer) {
	o.customProducers[mediaType] = producer
}

// AddMiddlewareFor adds a http middleware to existing handler
func (o *APIClarityAPIsAPI) AddMiddlewareFor(method, path string, builder middleware.Builder) {
	um := strings.ToUpper(method)
	if path == "/" {
		path = ""
	}
	o.Init()
	if h, ok := o.handlers[um][path]; ok {
		o.handlers[method][path] = builder(h)
	}
}
