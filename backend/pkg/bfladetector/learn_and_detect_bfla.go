package bfladetector

import (
	"context"
	"gopkg.in/yaml.v3"
	"net/url"
	"time"

	"github.com/apiclarity/apiclarity/api/server/models"
	"github.com/apiclarity/apiclarity/backend/pkg/database"
	"github.com/apiclarity/apiclarity/backend/pkg/k8straceannotator"
	log "github.com/sirupsen/logrus"
)

type NamespacedBFLADetector interface {
	Run(ctx context.Context)
	Done() <-chan struct{}

	SendTrace(trace *k8straceannotator.K8SAnnotatedK8STelemetry)
	ApproveTrace(event *database.APIEvent)
	DenyTrace(event *database.APIEvent)
}

type learnAndDetectBFLA struct {
	namespace                    string
	learningBegins, learningEnds time.Time
	tracesCh                     chan *k8straceannotator.K8SAnnotatedK8STelemetry
	suspiciousTracesCh           chan<- *k8straceannotator.K8SAnnotatedK8STelemetry
	approveTraceCh               chan *database.APIEvent
	denyTraceCh                  chan *database.APIEvent
	doneCh                       chan struct{}
	errCh                        chan error
	repo                         AuthzModelRepository
	openapiProvider              OpenAPIProvider
	learnTracesNr                int
}

func (l *learnAndDetectBFLA) Run(ctx context.Context) {
	data, err := l.repo.Load(ctx, l.namespace)
	if err != nil {
		l.errCh <- err
		data = &NamespaceAuthorizationModel{Services: map[string]*AuthorizationModel{}}
	}

	for {
		log.Infof("Waiting for traces tracesProcessed=%d", data.TracesProcessed)
		select {
		case trace := <-l.approveTraceCh:
			servicesUpdated := l.appendTelemetryToAuthzModel(
				trace.SourceK8sObject.Name,
				trace.DestinationK8sObject.Name,
				trace.Path,
				string(trace.Method),
				(*models.K8sObjectRef)(trace.SourceK8sObject),
				(*models.K8sObjectRef)(trace.DestinationK8sObject),
				data.Services)
			if servicesUpdated {
				log.Infof("Approved trace id=%s", trace.RequestID)
				val, err := l.repo.Store(ctx, &NamespaceAuthorizationModel{
					ID:              data.ID,
					FirstTraceAt:    l.learningBegins,
					LearningEndedAt: l.learningEnds,
					Namespace:       l.namespace,
					Services:        data.Services,
					TracesProcessed: data.TracesProcessed,
				})
				if err != nil {
					l.errCh <- err
					return
				}
				data = val
			} else {
				log.Infof("Trace trace id=%s already approved", trace.RequestID)
			}
		case req := <-l.denyTraceCh:
			serviceUpdated := false
			destName := req.DestinationK8sObject.Name
			resolvedPath := l.rezolvePath(destName, req.Path)
			model, ok := data.Services[destName]
			if !ok {
				log.Errorf("service %q not found", destName)
				continue
			}
			opIndex, op := model.Operations.Find(func(op *Operation) bool {
				return op.Path == resolvedPath && op.Method == string(req.Method)
			})
			if op != nil {
				audIndex, aud := op.Audience.Find(func(sa *ServiceAccount) bool {
					return sa.Name == req.SourceK8sObject.Name
				})
				if aud != nil {
					data.Services[destName].Operations[opIndex].Audience = append(data.Services[destName].Operations[opIndex].Audience[:audIndex], op.Audience[audIndex+1:]...)
					serviceUpdated = true
				}
				if len(op.Audience) == 0 {
					data.Services[destName].Operations = append(data.Services[destName].Operations[:opIndex], model.Operations[opIndex+1:]...)
					serviceUpdated = true
				}
			}
			if serviceUpdated {
				if _, err := l.repo.Store(ctx, data); err != nil {
					l.errCh <- err
					continue
				}
			}
		case trace, ok := <-l.tracesCh:
			if !ok {
				log.Info("Finished learning")
				return
			}

			log.Info("try to learn or detect BFLA data.TracesProcessed=", data.TracesProcessed)

			//TODO if trace.TraceTime.After(learningEnds) {
			if data.TracesProcessed > l.learnTracesNr {
				l.detectBFLAViolations(data.Services, trace, l.suspiciousTracesCh)
			} else {
				servicesUpdated := l.appendTelemetryToAuthzModel(
					trace.Source.K8SObject.Name,
					trace.Destination.K8SObject.Name,
					trace.SCNTRequest.Path,
					trace.SCNTRequest.Method,
					trace.Source.K8SObject,
					trace.Destination.K8SObject,
					data.Services)
				if servicesUpdated {
					log.Info("bfla synced for authz model with id=%s", data.ID)
					val, err := l.repo.Store(ctx, &NamespaceAuthorizationModel{
						ID:              data.ID,
						FirstTraceAt:    l.learningBegins,
						LearningEndedAt: l.learningEnds,
						Namespace:       l.namespace,
						Services:        data.Services,
						TracesProcessed: data.TracesProcessed,
					})
					if err != nil {
						l.errCh <- err
						return
					}
					data = val
				}
			}
			data.TracesProcessed++
			if err := l.repo.UpdateNrOfTraces(ctx, l.namespace, data.TracesProcessed); err != nil {
				l.errCh <- err
				return
			}
			// send the new updated model
		case <-ctx.Done():
			log.Info("ending learnFromTracesAndDetectBFLA")
			l.doneCh <- struct{}{}
			return
		}
	}
}

func (l *learnAndDetectBFLA) rezolvePath(host string, uri string) string {
	u, _ := url.Parse(uri)
	spec := l.getServiceOpenapiSpec(host)
	urlpath := u.Path
	if spec != nil {
		pathDef, _ := matchSpecAndPath(u.Path, spec)
		if pathDef != "" {
			return pathDef
		}
	}
	return urlpath
}

func (l *learnAndDetectBFLA) appendTelemetryToAuthzModel(aud, host, path, method string, src, dst *models.K8sObjectRef, services map[string]*AuthorizationModel) (servicesUpdated bool) {
	resolvedPath := l.rezolvePath(host, path)
	authzModel, ok := services[host]
	if ok {
		_, op := authzModel.Operations.Find(func(op *Operation) bool {
			return op.Method == method && op.Path == resolvedPath
		})
		if op == nil {
			authzModel.Operations = append(authzModel.Operations, &Operation{
				Method:   method,
				Path:     resolvedPath,
				Audience: []*ServiceAccount{{Name: aud, K8sObject: src}},
			})
		} else if _, audience := op.Audience.Find(func(sa *ServiceAccount) bool { return sa.Name == aud }); audience == nil {
			op.Audience = append(op.Audience, &ServiceAccount{Name: aud, K8sObject: src})
		} else {
			return false
		}
	} else {
		authzModel = &AuthorizationModel{
			ServiceName: host,
			K8sObject:   dst,
			Operations: []*Operation{{
				Method:   method,
				Path:     resolvedPath,
				Audience: []*ServiceAccount{{Name: aud, K8sObject: src}},
			}},
		}
	}
	services[host] = authzModel
	return true
}

func (l *learnAndDetectBFLA) detectBFLAViolations(services map[string]*AuthorizationModel, trace *k8straceannotator.K8SAnnotatedK8STelemetry, suspiciousTracesCh chan<- *k8straceannotator.K8SAnnotatedK8STelemetry) {
	if authzModel, ok := services[trace.Destination.K8SObject.Name]; ok {
		_, op := authzModel.Operations.Find(func(op *Operation) bool {
			return op.Path == l.rezolvePath(trace.Destination.K8SObject.Name, trace.SCNTRequest.Path) && op.Method == trace.SCNTRequest.Method
		})
		if op != nil {
			_, aud := op.Audience.Find(func(sa *ServiceAccount) bool {
				return sa.Name == trace.Source.K8SObject.Name
			})
			if aud != nil {
				return
			}
		}
	}
	suspiciousTracesCh <- trace
}

type GenericOpenapiSpec struct {
	Paths map[string]*Path `yaml:"paths"`
}

type Path struct {
	Ref         string                    `yaml:"$ref,omitempty"`
	Summary     string                    `yaml:"summary,omitempty"`
	Description string                    `yaml:"description,omitempty"`
	Servers     interface{}               `yaml:"servers,omitempty"`
	Operations  map[string]*HasParameters `yaml:",inline"`
	Parameters  []*Parameter              `yaml:"parameters,omitempty"`
}

type HasParameters struct {
	Parameters []*Parameter `yaml:"parameters,omitempty"`
}

type Parameter struct {
	Name string `yaml:"name,omitempty"`
	In   string `yaml:"in,omitempty"`
}

func (l *learnAndDetectBFLA) getServiceOpenapiSpec(serviceName string) *GenericOpenapiSpec {
	//p.management.V2ApiServiceAccountProvidedSpecGetImplicitAccount()
	reader, err := l.openapiProvider.GetOpenAPI(serviceName)
	if err != nil {
		log.Error(err)
		return nil
	}
	s := &GenericOpenapiSpec{}
	if err := yaml.NewDecoder(reader).Decode(s); err != nil {
		log.Error(err)
		return nil
	}
	return s
}

func (l *learnAndDetectBFLA) Done() <-chan struct{} { return l.doneCh }

func (l *learnAndDetectBFLA) SendTrace(trace *k8straceannotator.K8SAnnotatedK8STelemetry) {
	l.tracesCh <- trace
}

func (l *learnAndDetectBFLA) ApproveTrace(trace *database.APIEvent) {
	l.approveTraceCh <- trace
	return
}

func (l *learnAndDetectBFLA) DenyTrace(trace *database.APIEvent) {
	l.denyTraceCh <- trace
	return
}
