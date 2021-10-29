package k8straceannotator

import (
	"context"
	"errors"
	"strings"

	_spec "github.com/apiclarity/speculator/pkg/spec"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
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

func New(ctx context.Context, clientset kubernetes.Interface) (proc *k8senrichment, err error) {
	stopCh := make(chan struct{})
	k8sclient, err := NewK8sClient(stopCh, clientset)
	if err != nil {
		return nil, err
	}
	proc = &k8senrichment{
		errCh:  make(chan error),
		stopCh: make(chan struct{}),
		k8s:    k8sclient,
	}
	go func() {
		for {
			select {
			case err := <-proc.errCh:
				log.Info("ERROR: proc: ", err)
			case <-ctx.Done():
				log.Info("ERROR: context: ", ctx.Err())
			}
		}
	}()
	return
}

type k8senrichment struct {
	k8s    K8sClient
	errCh  chan error
	stopCh chan struct{}
}

func (p *k8senrichment) Run(ctx context.Context, tracesCh <-chan *_spec.SCNTelemetry) <-chan *K8SAnnotatedK8STelemetry {
	enrichedTracesCh := make(chan *K8SAnnotatedK8STelemetry)
	go func() {
		for {
			trace, ok := <-tracesCh
			if !ok {
				close(enrichedTracesCh)
				break
			}
			log.Infof("K8s enrichment trace: %q", trace.RequestID)
			destIp, _ := ParseAddr(trace.DestinationAddress)
			srcIp, _ := ParseAddr(trace.SourceAddress)
			//runtime.Object
			var srcObj, destObj runtime.Object
			svc, err := p.lookupServices(ctx, destIp)
			if err != nil {
				p.errCh <- err
				continue
			}
			if svc != nil {
				destObj = svc
			} else { //source ip (Pod -> ReplicaSet -> Deployment) =	> destination ip (Service -x Deployment)
				pod, err := p.lookupPods(ctx, destIp)
				if err != nil {
					p.errCh <- err
					continue
				}
				if pod != nil {
					destObj = pod
				} else {
					p.errCh <- errors.New("unable to find destination k8s object")
					continue
				}
			}
			pod, err := p.lookupPods(ctx, srcIp)
			if err != nil {
				p.errCh <- err
				continue
			}
			if pod == nil {
				p.errCh <- errors.New("unable to find source k8s object")
				continue
			}
			obj, err := p.k8s.GetObjectOwnerRecursively(ctx, pod.Namespace, pod.GetOwnerReferences())
			if err != nil {
				p.errCh <- err
				continue
			}
			if obj != nil {
				srcObj = obj
			} else {
				log.Info("src pod", pod.Name)
				srcObj = pod
			}

			enrichedTracesCh <- NewK8SAnnotatedK8STelemetry(trace, srcObj, destObj)
		}
	}()
	return enrichedTracesCh
}

func (p *k8senrichment) Stop() error {
	close(p.stopCh)
	return nil
}

func (p *k8senrichment) lookupServices(ctx context.Context, wantIp string) (*corev1.Service, error) {
	services, err := p.k8s.ServicesList("")
	if err != nil {
		return nil, err
	}
	for _, svc := range services {
		for _, ip := range svc.Spec.ClusterIPs {
			if ip == wantIp {
				return svc, nil
			}
		}
	}
	return nil, nil
}

func (p *k8senrichment) lookupPods(ctx context.Context, wantIp string) (*corev1.Pod, error) {
	pods, err := p.k8s.PodsList("")
	if err != nil {
		return nil, err
	}
	for _, pod := range pods {
		for _, ip := range pod.Status.PodIPs {
			if ip.IP == wantIp {
				return pod, nil
			}
		}
	}
	return nil, nil
}

func ParseAddr(addr string) (ip, port string) {
	parts := strings.Split(addr, ":")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return addr, ""
}

func hostHeader(trace *TraceMessage) (string, bool) {
	for _, h := range trace.ScntResponse.Headers {
		if h[0] == "host" {
			//Fri, 17 Sep 2021 10:12:32 GMT
			return h[1], true
		}
	}
	return "", false
}
