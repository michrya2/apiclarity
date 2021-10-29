package bfladetector

import (
	"context"
	"errors"
	"io"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/apiclarity/apiclarity/backend/pkg/k8straceannotator"
	"github.com/apiclarity/speculator/pkg/spec"
)

type TraceMessage struct {
	RequestId            string        `json:"request_id"`
	Scheme               string        `json:"scheme"`
	DestinationAddress   string        `json:"destination_address"`
	DestinationNamespace string        `json:"destination_namespace"`
	SourceAddress        string        `json:"source_address"`
	ScntRequest          *ScntRequest  `json:"scnt_request"`
	ScntResponse         *ScntResponse `json:"scnt_response"`
}

type ScntRequest struct {
	Method        string      `json:"method"`
	Path          string      `json:"path"`
	Host          string      `json:"host"`
	Version       string      `json:"version"`
	Headers       [][2]string `json:"headers"`
	Body          []byte      `json:"body"`
	TruncatedBody bool        `json:"truncated_body"`
}

type ScntResponse struct {
	StatusCode    string      `json:"status_code"`
	Version       string      `json:"version"`
	Headers       [][2]string `json:"headers"`
	Body          []byte      `json:"body"`
	TruncatedBody bool        `json:"truncated_body"`
}

type OpenAPIProvider interface {
	GetOpenAPI(serviceName string) (io.Reader, error)
}

func New(ctx context.Context, repo AuthzModelRepository, learnTracesNr int, openapiProvider OpenAPIProvider) (proc *bflaDetector, err error) {
	proc = &bflaDetector{
		repo:            repo,
		errCh:           make(chan error),
		learnTracesNr:   learnTracesNr,
		openapiProvider: openapiProvider,
	}
	go func() {
		for {
			select {
			case err := <-proc.errCh:
				log.Println("ERROR: proc: ", err)
			case <-ctx.Done():
				log.Println("ERROR: context: ", ctx.Err())
			}
		}
	}()
	return proc, nil
}

type bflaDetector struct {
	repo            AuthzModelRepository
	openapiProvider OpenAPIProvider
	errCh           chan error
	learnTracesNr   int
}

func (p *bflaDetector) ApproveTrace(traceID string) error {
	return nil
}

func (p *bflaDetector) DenyTrace(traceID string) error {

	return nil
}

func (p *bflaDetector) Run(ctx context.Context, enrichedTraceCh <-chan *k8straceannotator.K8SAnnotatedK8STelemetry) <-chan *k8straceannotator.K8SAnnotatedK8STelemetry {
	suspiciousTracesCh := make(chan *k8straceannotator.K8SAnnotatedK8STelemetry)
	// namespace plus the time of the first occurrence or a trace for the namespaces
	namespaceInfo := map[string]chan *k8straceannotator.K8SAnnotatedK8STelemetry{}
	go func() {
		for {
			select {
			case trace, ok := <-enrichedTraceCh:
				if !ok {
					for _, learnTracesCh := range namespaceInfo {
						close(learnTracesCh)
					}
					return
				}
				traceTime, err := parseTraceTime(trace)
				if err != nil {
					p.errCh <- err
					continue
				}
				//trace.TraceTime = traceTime
				learnTracesCh, ok := namespaceInfo[trace.Destination.K8SObject.Namespace]
				if !ok {
					learnTracesCh = make(chan *k8straceannotator.K8SAnnotatedK8STelemetry)
					namespaceInfo[trace.Destination.K8SObject.Namespace] = learnTracesCh
					learningEnds := traceTime.Add(5 * time.Minute)
					log.Infof("Starting learning and detection for namespace=%s", trace.Destination.K8SObject.Namespace)
					p.learnFromTracesAndDetectBFLA(ctx, trace.Destination.K8SObject.Namespace, traceTime, learningEnds, learnTracesCh, suspiciousTracesCh)
				}
				log.Infof("Sending trace for processing trace=%v", trace)
				learnTracesCh <- trace

			case <-ctx.Done():
				return
			}
		}
	}()
	return suspiciousTracesCh
}

func (p *bflaDetector) detectBFLAViolations(services map[string]*AuthorizationModel, trace *k8straceannotator.K8SAnnotatedK8STelemetry, suspiciousTracesCh chan<- *k8straceannotator.K8SAnnotatedK8STelemetry) {
	if authzModel, ok := services[trace.Destination.K8SObject.Name]; ok {
		op := authzModel.Operations.Find(func(op *Operation) bool {
			return op.Path == p.rezolvePath(trace.Destination.K8SObject.Name, trace.SCNTRequest.Path) && op.Method == trace.SCNTRequest.Method
		})
		if op != nil {
			aud := op.Audience.Find(func(sa *ServiceAccount) bool {
				return sa.Name == trace.Source.K8SObject.Name
			})
			if aud != nil {
				return
			}
		}
	}
	suspiciousTracesCh <- trace
}

func (p *bflaDetector) rezolvePath(host string, uri string) string {
	u, _ := url.Parse(uri)
	spec := p.getServiceOpenapiSpec(host)
	urlpath := u.Path
	if spec != nil {
		pathDef, _ := matchSpecAndPath(u.Path, spec)
		if pathDef != "" {
			return pathDef
		}
	}
	return urlpath
}

//TODO integrate with management
//TODO smarter learning algo
//TODO enhance AuthzModel with k8s data
func (p *bflaDetector) learnFromServiceInteractions(trace *k8straceannotator.K8SAnnotatedK8STelemetry, services map[string]*AuthorizationModel) (servicesUpdated bool) {
	aud := trace.Source.K8SObject.Name
	host := trace.Destination.K8SObject.Name
	resolvedPath := p.rezolvePath(host, trace.SCNTRequest.Path)
	authzModel, ok := services[host]
	if ok {
		op := authzModel.Operations.Find(func(op *Operation) bool {
			return op.Method == trace.SCNTRequest.Method && op.Path == resolvedPath
		})
		if op == nil {
			authzModel.Operations = append(authzModel.Operations, &Operation{
				Method:   trace.SCNTRequest.Method,
				Path:     resolvedPath,
				Audience: []*ServiceAccount{{Name: aud, K8sObject: trace.Source.K8SObject}},
			})
		} else if op.Audience.Find(func(sa *ServiceAccount) bool { return sa.Name == aud }) == nil {
			op.Audience = append(op.Audience, &ServiceAccount{Name: aud, K8sObject: trace.Source.K8SObject})
		} else {
			return false
		}
	} else {
		authzModel = &AuthorizationModel{
			ServiceName: host,
			K8sObject:   trace.Destination.K8SObject,
			Operations: []*Operation{{
				Method:   trace.SCNTRequest.Method,
				Path:     resolvedPath,
				Audience: []*ServiceAccount{{Name: aud, K8sObject: trace.Source.K8SObject}},
			}},
		}
	}
	services[host] = authzModel
	return true
}

func (p *bflaDetector) learnFromTracesAndDetectBFLA(ctx context.Context, namespace string, learningBegins, learningEnds time.Time, tracesCh <-chan *k8straceannotator.K8SAnnotatedK8STelemetry, suspiciousTracesCh chan<- *k8straceannotator.K8SAnnotatedK8STelemetry) {

	go func() {
		data, err := p.repo.Load(ctx, namespace)
		if err != nil {
			p.errCh <- err
			data = &NamespaceAuthorizationModel{Services: map[string]*AuthorizationModel{}}
		}

		for {
			log.Infof("waiting for traces tracesProcessed=%d", data.TracesProcessed)
			select {

			case trace, ok := <-tracesCh:
				if !ok {
					log.Info("Finished learning")
					return
				}

				log.Info("try to learn or detect BFLA data.TracesProcessed=", data.TracesProcessed)

				//TODO if trace.TraceTime.After(learningEnds) {
				if data.TracesProcessed > p.learnTracesNr {
					p.detectBFLAViolations(data.Services, trace, suspiciousTracesCh)
				} else {
					servicesUpdated := p.learnFromServiceInteractions(trace, data.Services)
					if servicesUpdated {
						log.Info("bfla synced for authz model with id=%s", data.ID)
						val, err := p.repo.Store(ctx, &NamespaceAuthorizationModel{
							ID:              data.ID,
							FirstTraceAt:    learningBegins,
							LearningEndedAt: learningEnds,
							Namespace:       namespace,
							Services:        data.Services,
							TracesProcessed: data.TracesProcessed,
						})
						if err != nil {
							p.errCh <- err
							return
						}
						data = val
					}
				}
				data.TracesProcessed++
				if err := p.repo.UpdateNrOfTraces(ctx, namespace, data.TracesProcessed); err != nil {
					p.errCh <- err
					return
				}
				// send the new updated model
			case <-ctx.Done():
				log.Info("ending learnFromTracesAndDetectBFLA")
				return
			}
		}
	}()
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

func (p *bflaDetector) getServiceOpenapiSpec(serviceName string) *GenericOpenapiSpec {
	//p.management.V2ApiServiceAccountProvidedSpecGetImplicitAccount()
	reader, err := p.openapiProvider.GetOpenAPI(serviceName)
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

func matchSpecAndPath(path string, spec *GenericOpenapiSpec) (pathDef string, paramValues map[string]string) {
	pathSplit := strings.Split(path, "/")
pathsLoop:
	for pathDefKey, pathItem := range spec.Paths {
		params := map[string]string{}
		//log.Println("pathDefKey", pathDefKey, path)
		for _, param := range pathItem.Parameters {
			if param.In == "path" {
				params[param.Name] = ""
			}
		}
		for _, op := range pathItem.Operations {
			for _, param := range op.Parameters {
				if param.In == "path" {
					params[param.Name] = ""
				}
			}
		}

		pathDefSplit := strings.Split(pathDefKey, "/")
		if len(pathDefSplit) != len(pathSplit) {
			continue
		}
		for i := range pathDefSplit {
			if pathDefSplit[i] == pathSplit[i] {
				if i == len(pathSplit)-1 {
					return pathDefKey, params
				}
				continue
			}
			pathPart := strings.TrimLeft(strings.TrimRight(pathDefSplit[i], "}"), "{")
			if _, ok := params[pathPart]; ok && strings.HasSuffix(pathDefSplit[i], "}") && strings.HasPrefix(pathDefSplit[i], "{") {
				params[pathPart] = pathSplit[i]
				if i == len(pathSplit)-1 {
					return pathDefKey, params
				}
				continue
			}
			continue pathsLoop
		}
	}
	return "", nil
}

func parseTraceTime(trace *k8straceannotator.K8SAnnotatedK8STelemetry) (time.Time, error) {
	headersMap := spec.ConvertHeadersToMap(trace.SCNTResponse.Headers)
	if dateHeader, ok := headersMap["date"]; ok {
		//Fri, 17 Sep 2021 10:12:32 GMT
		tm, err := time.Parse(time.RFC1123, dateHeader)
		if err != nil {
			log.Fatal(err)
		}
		return tm, err
	}
	return time.Time{}, errors.New("trace missing date header")
}

//LocalFolderOpenapiProvider is a OpenAPI provided that tries to get the specs form a local folder
type LocalFolderOpenapiProvider string

func (folder LocalFolderOpenapiProvider) GetOpenAPI(serviceName string) (io.Reader, error) {
	f, err := os.Open(path.Join(string(folder), serviceName+".json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f, nil
}
