package bfladetector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/apiclarity/apiclarity/api/server/models"
	"github.com/apiclarity/apiclarity/backend/pkg/database"
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

type BFLADetector interface {
	Run(ctx context.Context, enrichedTraceCh <-chan *k8straceannotator.K8SAnnotatedK8STelemetry) <-chan *k8straceannotator.K8SAnnotatedK8STelemetry
	ApproveAPIEvent(ctx context.Context, id uint32) error
	DenyAPIEvent(ctx context.Context, id uint32) error
}

func New(ctx context.Context, repo AuthzModelRepository, learnTracesNr int, openapiProvider OpenAPIProvider) (proc *bflaDetector, err error) {
	proc = &bflaDetector{
		repo:            repo,
		openapiProvider: openapiProvider,
		errCh:           make(chan error),
		learnTracesNr:   learnTracesNr,
		approveTraceCh:  make(chan uint32),
		denyTraceCh:     make(chan uint32),
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

	approveTraceCh chan uint32
	denyTraceCh    chan uint32
}

func (p *bflaDetector) initLearnAndDetectBFLA(namespace string, suspiciousTracesCh chan *k8straceannotator.K8SAnnotatedK8STelemetry) *learnAndDetectBFLA {
	return &learnAndDetectBFLA{
		namespace:          namespace,
		tracesCh:           make(chan *k8straceannotator.K8SAnnotatedK8STelemetry),
		suspiciousTracesCh: suspiciousTracesCh,
		approveTraceCh:     make(chan *database.APIEvent),
		denyTraceCh:        make(chan *database.APIEvent),
		doneCh:             make(chan struct{}),
		errCh:              make(chan error),
		repo:               p.repo,
		openapiProvider:    p.openapiProvider,
		learnTracesNr:      p.learnTracesNr,
	}
}

func (p *bflaDetector) ApproveAPIEvent(ctx context.Context, id uint32) error {
	select {
	case p.approveTraceCh <- id:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}
func (p *bflaDetector) DenyAPIEvent(ctx context.Context, id uint32) error {
	select {
	case p.denyTraceCh <- id:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func (p *bflaDetector) Run(ctx context.Context, enrichedTraceCh <-chan *k8straceannotator.K8SAnnotatedK8STelemetry) <-chan *k8straceannotator.K8SAnnotatedK8STelemetry {
	suspiciousTracesCh := make(chan *k8straceannotator.K8SAnnotatedK8STelemetry)
	// namespace plus the time of the first occurrence or a trace for the namespaces
	namespaceInfo := map[string]NamespacedBFLADetector{}
	go func() {
		for {
			select {
			case traceID := <-p.approveTraceCh:
				log.Infof("Request approve trace event id=%d", traceID)
				apiEvent, err := database.GetAPIEvent(traceID)
				if err != nil {
					p.errCh <- fmt.Errorf("API event with id=%q not found: %s", traceID, err)
					continue
				}
				if namespacedDetector, ok := namespaceInfo[apiEvent.DestinationK8sObject.Namespace]; ok {
					namespacedDetector.ApproveTrace(apiEvent)
				} else {
					namespacedDetector = p.initLearnAndDetectBFLA(apiEvent.DestinationK8sObject.Namespace, suspiciousTracesCh)
					go namespacedDetector.Run(ctx)
					namespaceInfo[apiEvent.DestinationK8sObject.Namespace] = namespacedDetector
					log.Infof("Starting learning and detection for namespace=%s", apiEvent.DestinationK8sObject.Namespace)
				}
				if err := database.UpdateAPIEventBFLAStatusByPathMethodSrcDest(apiEvent.Path,
					string(apiEvent.Method),
					apiEvent.DestinationK8sObject.Name,
					apiEvent.SourceK8sObject.Name,
					""); err != nil {
					p.errCh <- fmt.Errorf("unable to update past traces: err=%s", err)
					continue
				}

			case traceID := <-p.denyTraceCh:
				log.Infof("Request deny trace event id=%d", traceID)
				apiEvent, err := database.GetAPIEvent(traceID)
				if err != nil {
					p.errCh <- fmt.Errorf("API event with id=%d not found: %s", traceID, err)
					continue
				}
				if namespacedDetector, ok := namespaceInfo[apiEvent.DestinationK8sObject.Namespace]; ok {
					namespacedDetector.DenyTrace(apiEvent)
				} else {
					namespacedDetector = p.initLearnAndDetectBFLA(apiEvent.DestinationK8sObject.Namespace, suspiciousTracesCh)
					go namespacedDetector.Run(ctx)
					namespaceInfo[apiEvent.DestinationK8sObject.Namespace] = namespacedDetector
					log.Infof("Starting learning and detection for namespace=%s", apiEvent.DestinationK8sObject.Namespace)
				}
				if err := database.UpdateAPIEventBFLAStatusByPathMethodSrcDest(apiEvent.Path,
					string(apiEvent.Method),
					apiEvent.DestinationK8sObject.Name,
					apiEvent.SourceK8sObject.Name,
					resolveBFLAStatusInt(int(apiEvent.StatusCode))); err != nil {
					p.errCh <- fmt.Errorf("unable to update past traces: err=%s", err)
					continue
				}
			case trace, ok := <-enrichedTraceCh:
				if !ok {
					return
				}
				//traceTime, err := parseTraceTime(trace)
				//if err != nil {
				//	p.errCh <- err
				//	continue
				//}
				//trace.TraceTime = traceTime
				namespacedDetector, ok := namespaceInfo[trace.Destination.K8SObject.Namespace]
				if !ok {
					namespacedDetector = p.initLearnAndDetectBFLA(trace.Destination.K8SObject.Namespace, suspiciousTracesCh)
					go namespacedDetector.Run(ctx)
					namespaceInfo[trace.Destination.K8SObject.Namespace] = namespacedDetector
					log.Infof("Starting learning and detection for namespace=%s", trace.Destination.K8SObject.Namespace)
				}
				log.Infof("Sending trace for processing trace=%v", trace)
				namespacedDetector.SendTrace(trace)

			case <-ctx.Done():
				return
			}
		}
	}()
	return suspiciousTracesCh
}

func ResolveBFLAStatus(statusCode string) models.BFLAStatus {
	code, err := strconv.Atoi(statusCode)
	if err == nil {
		return resolveBFLAStatusInt(code)
	}

	return models.BFLAStatusSUSPICIOUSSRCALLOWED
}

func resolveBFLAStatusInt(code int) models.BFLAStatus {
	if 200 > code || code > 299 {
		return models.BFLAStatusSUSPICIOUSSRCDENIED
	}

	return models.BFLAStatusSUSPICIOUSSRCALLOWED
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
