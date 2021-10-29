package k8straceannotator

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"sync"

	"github.com/apiclarity/apiclarity/api/server/models"
	"github.com/apiclarity/speculator/pkg/spec"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	memory "k8s.io/client-go/discovery/cached"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/cache"
)

func NewK8SAnnotatedK8STelemetry(trace *spec.SCNTelemetry, src, dest runtime.Object) *K8SAnnotatedK8STelemetry {
	return &K8SAnnotatedK8STelemetry{
		OriginalTrace: trace,
		RequestId:     trace.RequestID,
		Scheme:        trace.Scheme,
		Destination: &AppEnvInfo{
			Address:   trace.DestinationAddress,
			K8SObject: NewRef(dest),
		},
		Source: &AppEnvInfo{
			Address:   trace.SourceAddress,
			K8SObject: NewRef(src),
		},
		SCNTRequest:  &trace.SCNTRequest,
		SCNTResponse: &trace.SCNTResponse,
	}
}

type K8SAnnotatedK8STelemetry struct {
	OriginalTrace *spec.SCNTelemetry
	RequestId     string
	Scheme        string
	Destination   *AppEnvInfo
	Source        *AppEnvInfo
	SCNTRequest   *spec.SCNTRequest
	SCNTResponse  *spec.SCNTResponse
}

type AppEnvInfo struct {
	Address   string
	Namespace string
	K8SObject *models.K8sObjectRef
}

func NewRef(obj runtime.Object) *models.K8sObjectRef {
	gvk := obj.GetObjectKind().GroupVersionKind()
	metaObj, err := meta.Accessor(obj)
	if err != nil {
		log.Error("k8s object does not implement metadata")
		return nil
	}
	return &models.K8sObjectRef{
		Kind:       gvk.Kind,
		APIVersion: gvk.GroupVersion().String(),
		Namespace:  metaObj.GetNamespace(),
		Name:       metaObj.GetName(),
		UID:        string(metaObj.GetUID()),
	}
}

type K8sClient interface {
	ServicesGet(namespace, name string) (*corev1.Service, error)
	ServicesList(namespace string) ([]*corev1.Service, error)
	PodsList(namespace string) ([]*corev1.Pod, error)

	GetObject(ctx context.Context, apiVersion, kind, namespace, name string) (runtime.Object, error)
	GetObjectOwnerRecursively(ctx context.Context, namespace string, refs []metav1.OwnerReference) (runtime.Object, error)
}

type client struct {
	restMapper      meta.RESTMapper //TODO private
	informerFactory informers.SharedInformerFactory
	stopCh          <-chan struct{}

	servicesOnce *sync.Once
	podsOnce     *sync.Once

	resourcesOnce map[schema.GroupVersionResource]struct{}
	resourcesMu   *sync.RWMutex
}

func NewK8sClient(stopCh <-chan struct{}, clientset kubernetes.Interface) (*client, error) {
	rm := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(clientset.Discovery()))
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)
	return &client{rm, informerFactory,
		stopCh,
		&sync.Once{}, &sync.Once{}, map[schema.GroupVersionResource]struct{}{}, &sync.RWMutex{},
	}, nil
}

func (c *client) GetObjectOwnerRecursively(ctx context.Context, namespace string, refs []metav1.OwnerReference) (runtime.Object, error) {
	for _, ref := range refs {
		obj, err := c.GetObject(ctx, ref.APIVersion, ref.Kind, namespace, ref.Name)
		if err != nil {
			return nil, err
		}
		metaObj, err := meta.Accessor(obj)
		if err != nil {
			return obj, err
		}
		ownerObj, err := c.GetObjectOwnerRecursively(ctx, namespace, metaObj.GetOwnerReferences())
		if err != nil {
			return nil, err
		}
		// if no parent is fount return the current object
		if ownerObj == nil {
			return obj, nil
		}
		return ownerObj, nil
	}
	return nil, nil
}

func (c *client) ServicesGet(namespace, name string) (obj *corev1.Service, _ error) {
	informer := c.informerFactory.Core().V1().Services()
	c.servicesOnce.Do(func() {
		go informer.Informer().Run(c.stopCh)
		cache.WaitForCacheSync(c.stopCh, informer.Informer().HasSynced)
		log.Info("synced resources for: Services")
	})
	defer func() {
		_ = addObjectTypeMeta(obj)
	}()
	return informer.Lister().Services(namespace).Get(name)
}

func (c *client) ServicesList(namespace string) (objs []*corev1.Service, err error) {
	informer := c.informerFactory.Core().V1().Services()
	c.servicesOnce.Do(func() {
		go informer.Informer().Run(c.stopCh)
		cache.WaitForCacheSync(c.stopCh, informer.Informer().HasSynced)
		log.Info("synced resources for: Services")
	})
	defer func() {
		for _, i := range objs {
			_ = addObjectTypeMeta(i)
		}
	}()
	return informer.Lister().Services(namespace).List(labels.Everything())
}

func (c *client) PodsList(namespace string) (objs []*corev1.Pod, _ error) {
	informer := c.informerFactory.Core().V1().Pods()
	c.podsOnce.Do(func() {
		go informer.Informer().Run(c.stopCh)
		cache.WaitForCacheSync(c.stopCh, informer.Informer().HasSynced)
		log.Info("synced resources for: Pods")
	})
	defer func() {
		for _, i := range objs {
			_ = addObjectTypeMeta(i)
		}
	}()
	return informer.Lister().Pods(namespace).List(labels.Everything())
}

func (c *client) GetObject(ctx context.Context, apiVersion, kind, namespace, name string) (runtime.Object, error) {
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return nil, err
	}
	gvk := schema.GroupVersionKind{
		Group:   gv.Group,
		Version: gv.Version,
		Kind:    kind,
	}
	mapping, err := c.restMapper.RESTMapping(schema.GroupKind{Kind: kind, Group: gv.Group}, gv.Version)
	if err != nil {
		return nil, fmt.Errorf("cannot map kind/group/version %w", err)
	}
	gvr := schema.GroupVersionResource{
		Group:    gv.Group,
		Version:  gv.Version,
		Resource: mapping.Resource.Resource,
	}
	informer, err := c.informerFactory.ForResource(gvr)
	if err != nil {
		return nil, err
	}
	c.resourcesMu.RLock()
	_, ok := c.resourcesOnce[gvr]
	c.resourcesMu.RUnlock()
	if !ok {
		c.resourcesMu.Lock()
		c.resourcesOnce[gvr] = struct{}{}
		c.resourcesMu.Unlock()
		go informer.Informer().Run(c.stopCh)
		cache.WaitForCacheSync(c.stopCh, informer.Informer().HasSynced)
		log.Info("synced resources for: ", gvr)
	}

	obj, err := scheme.Scheme.New(gvk)
	if err != nil {
		return nil, err
	}
	obj, err = informer.Lister().ByNamespace(namespace).Get(name)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve k8s object %w", err)
	}
	obj.GetObjectKind().SetGroupVersionKind(gvk)
	return obj, nil
}

func addObjectTypeMeta(obj runtime.Object) error {
	if !obj.GetObjectKind().GroupVersionKind().Empty() {
		return nil
	}
	gvks, _, err := scheme.Scheme.ObjectKinds(obj)
	if err != nil {
		return fmt.Errorf("missing apiVersion or kind and cannot assign it; %w", err)
	}
	for _, gvk := range gvks {
		if len(gvk.Kind) == 0 {
			continue
		}
		if len(gvk.Version) == 0 || gvk.Version == runtime.APIVersionInternal {
			continue
		}
		obj.GetObjectKind().SetGroupVersionKind(gvk)
		break
	}
	return nil
}
