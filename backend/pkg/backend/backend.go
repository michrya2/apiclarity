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

package backend

import (
	"context"
	"fmt"
	"mime"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-openapi/spec"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"sigs.k8s.io/yaml"

	"github.com/apiclarity/apiclarity/api/server/models"
	"github.com/apiclarity/apiclarity/backend/pkg/bfladetector"
	_config "github.com/apiclarity/apiclarity/backend/pkg/config"
	_database "github.com/apiclarity/apiclarity/backend/pkg/database"
	"github.com/apiclarity/apiclarity/backend/pkg/database/fake"
	"github.com/apiclarity/apiclarity/backend/pkg/healthz"
	"github.com/apiclarity/apiclarity/backend/pkg/k8smonitor"
	"github.com/apiclarity/apiclarity/backend/pkg/k8straceannotator"
	"github.com/apiclarity/apiclarity/backend/pkg/rest"
	"github.com/apiclarity/apiclarity/backend/pkg/traces"
	_spec "github.com/apiclarity/speculator/pkg/spec"
	_speculator "github.com/apiclarity/speculator/pkg/speculator"
	_mimeutils "github.com/apiclarity/speculator/pkg/utils"
)

type Backend struct {
	speculator          *_speculator.Speculator
	stateBackupInterval time.Duration
	stateBackupFileName string
	monitor             *k8smonitor.Monitor
	apiInventoryLock    sync.RWMutex
	telemetryCh         <-chan *k8straceannotator.K8SAnnotatedK8STelemetry
}

func CreateBackend(config *_config.Config, monitor *k8smonitor.Monitor, telemetryCh <-chan *k8straceannotator.K8SAnnotatedK8STelemetry) *Backend {
	speculator, err := _speculator.DecodeState(config.StateBackupFileName, config.SpeculatorConfig)
	if err != nil {
		log.Infof("No speculator state to decode, creating new: %v", err)
		speculator = _speculator.CreateSpeculator(config.SpeculatorConfig)
	} else {
		log.Infof("Using encoded speculator state")
	}
	return &Backend{
		speculator:          speculator,
		stateBackupInterval: time.Second * time.Duration(config.StateBackupIntervalSec),
		stateBackupFileName: config.StateBackupFileName,
		monitor:             monitor,
		telemetryCh:         telemetryCh,
	}
}

const defaultChanSize = 100

func Run() {
	config, err := _config.LoadConfig()
	if err != nil {
		log.Errorf("Failed to load config: %v", err)
		return
	}
	errChan := make(chan struct{}, defaultChanSize)

	healthServer := healthz.NewHealthServer(config.HealthCheckAddress)
	healthServer.Start(errChan)

	healthServer.SetIsReady(false)

	globalCtx, globalCancel := context.WithCancel(context.Background())
	defer globalCancel()

	log.Info("APIClarity backend is running")
	clientset, err := k8smonitor.CreateK8sClientset()
	if err != nil {
		log.Fatalf("failed to create K8s clientset: %v", err)
	}

	var monitor *k8smonitor.Monitor
	if !viper.GetBool(_database.FakeTracesEnvVar) && !viper.GetBool(_database.FakeDataEnvVar) {
		monitor, err = k8smonitor.CreateMonitor(clientset)
		if err != nil {
			log.Errorf("Failed to create a monitor: %v", err)
			return
		}
		monitor.Start()
		defer monitor.Stop()
	} else if viper.GetBool(_database.FakeDataEnvVar) {
		go fake.CreateFakeData()
	}

	tracesCh := make(chan *_spec.SCNTelemetry)
	defer close(tracesCh)
	k8sAnnotatedTrace1 := make(chan *k8straceannotator.K8SAnnotatedK8STelemetry)
	defer close(k8sAnnotatedTrace1)
	k8sAnnotatedTrace2 := make(chan *k8straceannotator.K8SAnnotatedK8STelemetry)
	defer close(k8sAnnotatedTrace2)

	backend := CreateBackend(config, monitor, k8sAnnotatedTrace1)
	backend.Run(globalCtx)
	k8sAnnorator, err := k8straceannotator.New(globalCtx, clientset)
	if err != nil {
		log.Fatal(err)
	}
	k8sAnnotatedTraceCh := k8sAnnorator.Run(globalCtx, tracesCh)

	go func() {
		for {
			select {
			case trace := <-k8sAnnotatedTraceCh:
				log.Infof("Fan out annotated trace %q", trace.RequestId)
				k8sAnnotatedTrace1 <- trace
				k8sAnnotatedTrace2 <- trace
			case <-globalCtx.Done():
				return
			}
		}
	}()
	authzmodelRepo := _database.NewAuthZModelRepository(_database.DB)
	const NrOfTracesToLearn = 200
	bflaDetector, err := bfladetector.New(globalCtx, authzmodelRepo, NrOfTracesToLearn, _database.BFLAOpenAPIProvider{})
	if err != nil {
		log.Fatal(err)
	}

	suspiciousTracesCh := bflaDetector.Run(globalCtx, k8sAnnotatedTrace2)
	go func() {
		for {
			select {
			case trace, ok := <-suspiciousTracesCh:
				if !ok {
					return
				}
				code, err := strconv.Atoi(trace.SCNTResponse.StatusCode)
				//srcIp, _ := getHostname(trace.Source.Address)
				//dstIp, _ := getHostname(trace.Destination.Address)
				if err == nil && (200 > code || code > 299) {
					err = _database.UpdateAPIEventBFLAStatus(trace.RequestId, models.BFLAStatusSUSPICIOUSSRCDENIED)
				} else {
					err = _database.UpdateAPIEventBFLAStatus(trace.RequestId, models.BFLAStatusSUSPICIOUSSRCALLOWED)
				}
				if err != nil {
					log.Errorf("unable to update the database record with bfla status: %s", err)
				}
			case <-globalCtx.Done():
				return
			}
		}
	}()

	tracesServer := traces.CreateHTTPTracesServer(config.HTTPTracesPort, func(trace *_spec.SCNTelemetry) error {
		tracesCh <- trace
		return nil
	})
	tracesServer.Start(errChan)
	defer tracesServer.Stop()

	restServer, err := rest.CreateRESTServer(config.BackendRestPort, backend.speculator, authzmodelRepo)
	if err != nil {
		log.Fatalf("Failed to create REST server: %v", err)
	}
	restServer.Start(errChan)
	defer restServer.Stop()

	backend.startStateBackup(globalCtx)
	startReviewTableCleaner(globalCtx, time.Duration(config.DatabaseCleanerIntervalSec)*time.Second)

	healthServer.SetIsReady(true)
	log.Info("APIClarity backend is ready")

	if viper.GetBool(_database.FakeTracesEnvVar) {
		go backend.startSendingFakeTraces()
	}

	// Wait for deactivation
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	select {
	case <-errChan:
		log.Errorf("Received an error - shutting down")
	case s := <-sig:
		log.Warningf("Received a termination signal: %v", s)
	}
}

func startReviewTableCleaner(ctx context.Context, cleanInterval time.Duration) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Debugf("Stopping database cleaner")
				return
			case <-time.After(cleanInterval):
				if err := _database.GetReviewTable().Where("approved =  ?", true).Delete(_database.Review{}).Error; err != nil {
					log.Errorf("Failed to delete approved review from database. %v", err)
				}
			}
		}
	}()
}

type eventDiff struct {
	Path     string
	PathItem *spec.PathItem
}

func convertSpecDiffToEventDiff(diff *_spec.APIDiff) (originalRet, modifiedRet []byte, err error) {
	original := eventDiff{
		Path:     diff.Path,
		PathItem: diff.OriginalPathItem,
	}
	modified := eventDiff{
		Path:     diff.Path,
		PathItem: diff.ModifiedPathItem,
	}
	originalRet, err = yaml.Marshal(original)
	if err != nil {
		return nil, nil, fmt.Errorf("failed marshal original: %v", err)
	}
	modifiedRet, err = yaml.Marshal(modified)
	if err != nil {
		return nil, nil, fmt.Errorf("failed marshal modified: %v", err)
	}

	return originalRet, modifiedRet, nil
}

func (b *Backend) Run(ctx context.Context) {
	go func() {
		for {
			select {
			case trace, ok := <-b.telemetryCh:
				if !ok {
					return
				}
				log.Infof("Backend handlet trace: %q", trace.RequestId)
				if err := b.handleHTTPTrace(trace); err != nil {
					log.Errorf("Failed to handle trace. err=%v", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (b *Backend) handleHTTPTrace(trace *k8straceannotator.K8SAnnotatedK8STelemetry) error {
	var reconstructedDiff *_spec.APIDiff
	var providedDiff *_spec.APIDiff
	var err error

	if trace.SCNTRequest.Host == "" {
		headers := _spec.ConvertHeadersToMap(trace.SCNTRequest.Headers)
		if host, ok := headers["host"]; ok {
			trace.SCNTRequest.Host = host
		}
	}

	trace.SCNTRequest.Host, err = getHostname(trace.SCNTRequest.Host)
	if err != nil {
		return fmt.Errorf("failed to get hostname from host: %v", err)
	}

	destInfo, err := _speculator.GetAddressInfoFromAddress(trace.Destination.Address)
	if err != nil {
		return fmt.Errorf("failed to get destination info: %v", err)
	}
	destPort, err := strconv.Atoi(destInfo.Port)
	if err != nil {
		return fmt.Errorf("failed to convert destination port: %v", err)
	}
	srcInfo, err := _speculator.GetAddressInfoFromAddress(trace.Source.Address)
	if err != nil {
		return fmt.Errorf("failed to get source info: %v", err)
	}

	// Initialize API info
	apiInfo := _database.APIInfo{
		Name: trace.SCNTRequest.Host,
		Port: int64(destPort),
	}

	// Set API Info type
	if b.monitor.IsInternalCIDR(destInfo.IP) {
		apiInfo.Type = models.APITypeINTERNAL
	} else {
		apiInfo.Type = models.APITypeEXTERNAL
	}

	isNonAPI := isNonAPI(trace.OriginalTrace)
	// Don't link non APIs to an API in the inventory
	if !isNonAPI {
		// lock the API inventory to avoid creating API entries twice on trace handling races
		b.apiInventoryLock.Lock()
		// TODO: Access the database via a database handler instance
		if err := _database.GetAPIInventoryTable().Where(apiInfo).FirstOrCreate(&apiInfo).Error; err != nil {
			b.apiInventoryLock.Unlock()
			return fmt.Errorf("failed to get or create API info: %v", err)
		}
		b.apiInventoryLock.Unlock()
		log.Infof("API Info in DB: %+v", apiInfo)

		// Handle trace telemetry by Speculator
		specKey := _speculator.GetSpecKey(trace.SCNTRequest.Host, destInfo.Port)
		if b.speculator.HasProvidedSpec(specKey) {
			providedDiff, err = b.speculator.DiffTelemetry(trace.OriginalTrace, _spec.DiffSourceProvided)
			if err != nil {
				return fmt.Errorf("failed to diff telemetry against provided spec: %v", err)
			}
		}
		if b.speculator.HasApprovedSpec(specKey) {
			reconstructedDiff, err = b.speculator.DiffTelemetry(trace.OriginalTrace, _spec.DiffSourceReconstructed)
			if err != nil {
				return fmt.Errorf("failed to diff telemetry against approved spec: %v", err)
			}
		} else {
			err := b.speculator.LearnTelemetry(trace.OriginalTrace)
			if err != nil {
				return fmt.Errorf("failed to learn telemetry: %v", err)
			}
		}
	}

	// Update API event in DB
	statusCode, err := strconv.Atoi(trace.SCNTResponse.StatusCode)
	if err != nil {
		return fmt.Errorf("failed to convert status code: %v", err)
	}

	path, query := _spec.GetPathAndQuery(trace.SCNTRequest.Path)

	event := &_database.APIEvent{
		APIInfoID:            apiInfo.ID,
		RequestID:            trace.RequestId,
		Time:                 strfmt.DateTime(time.Now().UTC()),
		Method:               models.HTTPMethod(trace.SCNTRequest.Method),
		Path:                 path,
		Query:                query,
		StatusCode:           int64(statusCode),
		SourceIP:             srcInfo.IP,
		DestinationIP:        destInfo.IP,
		DestinationPort:      int64(destPort),
		HostSpecName:         trace.SCNTRequest.Host,
		IsNonAPI:             isNonAPI,
		EventType:            apiInfo.Type,
		DestinationK8sObject: (*_database.K8sObjectRef)(trace.Destination.K8SObject),
		SourceK8sObject:      (*_database.K8sObjectRef)(trace.Source.K8SObject),
	}

	reconstructedDiffType := models.DiffTypeNODIFF
	if reconstructedDiff != nil {
		if reconstructedDiff.Type != _spec.DiffTypeNoDiff {
			original, modified, err := convertSpecDiffToEventDiff(reconstructedDiff)
			if err != nil {
				return fmt.Errorf("failed to convert spec diff to event diff: %v", err)
			}
			event.HasReconstructedSpecDiff = true
			event.HasSpecDiff = true
			event.OldReconstructedSpec = string(original)
			event.NewReconstructedSpec = string(modified)
		}
		event.ReconstructedPathID = reconstructedDiff.PathID
		reconstructedDiffType = convertAPIDiffType(reconstructedDiff.Type)
	}

	providedDiffType := models.DiffTypeNODIFF
	if providedDiff != nil {
		if providedDiff.Type != _spec.DiffTypeNoDiff {
			original, modified, err := convertSpecDiffToEventDiff(providedDiff)
			if err != nil {
				return fmt.Errorf("failed to convert spec diff to event diff: %v", err)
			}
			event.HasProvidedSpecDiff = true
			event.HasSpecDiff = true
			event.OldProvidedSpec = string(original)
			event.NewProvidedSpec = string(modified)
		}
		event.ProvidedPathID = providedDiff.PathID
		providedDiffType = convertAPIDiffType(providedDiff.Type)
	}

	event.SpecDiffType = getHighestPrioritySpecDiffType(providedDiffType, reconstructedDiffType)

	_database.CreateAPIEvent(event)

	return nil
}

func convertAPIDiffType(diffType _spec.DiffType) models.DiffType {
	switch diffType {
	case _spec.DiffTypeNoDiff:
		return models.DiffTypeNODIFF
	case _spec.DiffTypeShadowDiff:
		return models.DiffTypeSHADOWDIFF
	case _spec.DiffTypeZombieDiff:
		return models.DiffTypeZOMBIEDIFF
	case _spec.DiffTypeGeneralDiff:
		return models.DiffTypeGENERALDIFF
	default:
		log.Warnf("Unknown diff type: %v", diffType)
	}

	return models.DiffTypeNODIFF
}

//nolint:gomnd
var diffTypePriority = map[models.DiffType]int{
	// starting from 1 since unknown type will return 0
	models.DiffTypeNODIFF:      1,
	models.DiffTypeGENERALDIFF: 2,
	models.DiffTypeSHADOWDIFF:  3,
	models.DiffTypeZOMBIEDIFF:  4,
}

// getHighestPrioritySpecDiffType will return the type with the highest priority.
func getHighestPrioritySpecDiffType(providedDiffType, reconstructedDiffType models.DiffType) models.DiffType {
	if diffTypePriority[providedDiffType] > diffTypePriority[reconstructedDiffType] {
		return providedDiffType
	}

	return reconstructedDiffType
}

// getHostname will return only hostname without scheme and port
// ex. https://example.org:8000 --> example.org.
func getHostname(host string) (string, error) {
	if !strings.Contains(host, "://") {
		// need to add scheme to host in order for url.Parse to parse properly
		host = "http://" + host
	}

	parsedHost, err := url.Parse(host)
	if err != nil {
		return "", fmt.Errorf("failed to parse host. host=%v: %v", host, err)
	}

	if parsedHost.Hostname() == "" {
		return "", fmt.Errorf("hostname is empty. host=%v", host)
	}

	return parsedHost.Hostname(), nil
}

const (
	contentTypeHeaderName      = "content-type"
	contentTypeApplicationJSON = "application/json"
)

func isNonAPI(trace *_spec.SCNTelemetry) bool {
	respHeaders := _spec.ConvertHeadersToMap(trace.SCNTResponse.Headers)

	// If response content-type header is missing, we will classify it as API
	respContentType, ok := respHeaders[contentTypeHeaderName]
	if !ok {
		return false
	}

	mediaType, _, err := mime.ParseMediaType(respContentType)
	if err != nil {
		log.Errorf("Failed to parse response media type - classifying as non-API. Content-Type=%v: %v", respContentType, err)
		return true
	}

	// If response content-type is not application/json, need to classify the trace as non-api
	return !_mimeutils.IsApplicationJSONMediaType(mediaType)
}

func (b *Backend) startStateBackup(ctx context.Context) {
	go func() {
		stateBackupInterval := b.stateBackupInterval
		for {
			select {
			case <-ctx.Done():
				log.Debugf("Stopping state backup")
				return
			case <-time.After(stateBackupInterval):
				if err := b.speculator.EncodeState(b.stateBackupFileName); err != nil {
					log.Errorf("Failed to encode state: %v", err)
				}
			}
		}
	}()
}
