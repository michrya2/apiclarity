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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/apiclarity/apiclarity/backend/pkg/k8straceannotator"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/apiclarity/apiclarity/api/server/models"
	_spec "github.com/apiclarity/speculator/pkg/spec"
)

func (b *Backend) startSendingFakeTraces() {
	var files []string

	root := os.Getenv("FAKE_TRACES_PATH")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		files = append(files, path)
		return nil
	})
	if err != nil {
		log.Errorf("Failed to walk through files in folder: %v. %v", root, err)
		return
	}
	// send telemetries for learning
	for _, file := range files {
		if strings.Compare(file, root) == 0 {
			continue
		}

		if err := b.handleHTTPTraceFromFile(file); err != nil {
			log.Errorf("Failed to handle http trace from file: %v. %v", file, err)
		}
	}
	// upload provided spec
	putProvidedSpecLocally(root)
	time.Sleep(2 * time.Second)
	// send telemetry to diff against provided spec
	providedDiffTelemetryFile := root + "/../provided_spec/provided_spec_diff_telemetry.json"
	if err := b.handleHTTPTraceFromFile(providedDiffTelemetryFile); err != nil {
		log.Errorf("Failed to handle http trace from file: %v. %v", providedDiffTelemetryFile, err)
	}
	// sleep one minute to let the user approve the suggested spec (so we will have a reconstructed spec)
	time.Sleep(1 * time.Minute)
	// send telemetry to diff against reconstructed spec
	reconstructedDiffTelemetryFile := root + "/../diff_trace_files/httpbin_put_anything.json"
	if err := b.handleHTTPTraceFromFile(reconstructedDiffTelemetryFile); err != nil {
		log.Errorf("Failed to handle http trace from file: %v. %v", reconstructedDiffTelemetryFile, err)
	}
}

func (b *Backend) handleHTTPTraceFromFile(fileName string) error {
	byteValue, err := ioutil.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("failed to read file: %v. %v", fileName, err)
	}

	var trace _spec.SCNTelemetry
	if err := json.Unmarshal(byteValue, &trace); err != nil {
		return fmt.Errorf("failed to unmarshal. %v", err)
	}
	if err := b.handleHTTPTrace(k8straceannotator.NewK8SAnnotatedK8STelemetry(&trace, nil, nil)); err != nil {
		return fmt.Errorf("failed to handle trace for file: %v. %v", fileName, err)
	}
	return nil
}

func putProvidedSpecLocally(root string) {
	fileName := root + "/../provided_spec/provided_spec.json"

	// initialize http client
	client := &http.Client{}

	byteValue, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Errorf("Failed to read file: %v. %v", fileName, err)
		return
	}

	body := models.RawSpec{
		RawSpec: string(byteValue),
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}

	// set the HTTP method, url, and request body
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodPut, "http://localhost:8080/api/apiInventory/1/specs/providedSpec", bytes.NewBuffer(jsonBody))
	if err != nil {
		panic(fmt.Sprintf("Failed to create new request. %v", err))
	}

	// set the request header Content-Type for json
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := client.Do(req)
	if err != nil {
		panic(fmt.Sprintf("Request failed. %v", err))
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusCreated {
		log.Errorf("Failed to put provided spec locally, response status code is not 201. status code: %v", resp.StatusCode)
	}
}
