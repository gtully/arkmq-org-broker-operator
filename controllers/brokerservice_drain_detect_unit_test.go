/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/arkmq-org/arkmq-org-broker-operator/v2/api/v1beta2"
	"github.com/arkmq-org/arkmq-org-broker-operator/v2/pkg/brokerproperties"
	mgmt "github.com/arkmq-org/arkmq-org-broker-operator/v2/pkg/utils/artemis"
	"github.com/arkmq-org/arkmq-org-broker-operator/v2/pkg/utils/jolokia"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func buildMockQueueCountResponse(queues []mgmt.QueueMessageCount) map[string]interface{} {
	result := make(map[string]interface{}, len(queues))
	for _, qc := range queues {
		key := fmt.Sprintf(`org.apache.activemq.artemis:address="%s",broker="test-broker",component=addresses,queue="%s",routing-type="%s",subcomponent=queues`,
			qc.Address, qc.Queue, qc.RoutingType)
		result[key] = map[string]interface{}{"MessageCount": float64(qc.Count)}
	}
	return result
}

var _ = Describe("detectDrainingAddresses unit", func() {

	buildOldSecretData := func(app *v1beta2.BrokerApp, addresses ...string) map[string][]byte {
		caps := &brokerproperties.CapabilitiesJSON{
			AddressConfigurations: make(map[string]*brokerproperties.AddressConfiguration),
		}
		for _, addr := range addresses {
			caps.AddressConfigurations[addr] = &brokerproperties.AddressConfiguration{}
		}
		data, err := json.Marshal(caps)
		Expect(err).NotTo(HaveOccurred())
		capKey := AppIdentityPrefixed(app, "capabilities.json")
		return map[string][]byte{capKey: data}
	}

	It("skips drain detection when app was never provisioned", Label(unitLabel), func() {
		ns := "default"
		appName := "new-app"

		app := NewBrokerApp(appName, ns).
			WithAddresses(NewAddressType("orders").Build()).
			Build()

		reconciler := BrokerServiceInstanceReconcilerForTestWithInstance(ns, "test-service")

		oldSecretData := buildOldSecretData(app, "orders")
		emptyTracker := newAddressTracker()

		result := reconciler.detectDrainingAddresses(app, emptyTracker, oldSecretData)
		Expect(result).To(BeNil(), "should skip drain when app was never provisioned")
	})

	It("detects draining addresses when app was provisioned", Label(unitLabel), func() {
		ns := "default"
		appName := "provisioned-app"

		app := NewBrokerApp(appName, ns).
			WithAddresses(NewAddressType("orders").Build()).
			Build()

		reconciler := BrokerServiceInstanceReconcilerForTestWithInstance(ns, "test-service")
		reconciler.status.ProvisionedApps = []string{
			AppIdentityWithGeneration(app),
		}

		oldSecretData := buildOldSecretData(app, "orders")
		emptyTracker := newAddressTracker()

		// Jolokia is unavailable so all candidates are preserved as draining
		result := reconciler.detectDrainingAddresses(app, emptyTracker, oldSecretData)
		Expect(result).NotTo(BeNil(), "should detect draining addresses when app was provisioned")
		Expect(result).To(HaveLen(1))
		Expect(result[0].Address).To(Equal("orders"))
	})

	It("skips drain when a different app was provisioned but not this one", Label(unitLabel), func() {
		ns := "default"
		appName := "unprovisioned-app"
		otherAppName := "other-app"

		app := NewBrokerApp(appName, ns).
			WithAddresses(NewAddressType("orders").Build()).
			Build()
		otherApp := NewBrokerApp(otherAppName, ns).Build()

		reconciler := BrokerServiceInstanceReconcilerForTestWithInstance(ns, "test-service")
		reconciler.status.ProvisionedApps = []string{
			AppIdentityWithGeneration(otherApp),
		}

		oldSecretData := buildOldSecretData(app, "orders")
		emptyTracker := newAddressTracker()

		result := reconciler.detectDrainingAddresses(app, emptyTracker, oldSecretData)
		Expect(result).To(BeNil(), "should skip drain when only a different app was provisioned")
	})

	It("detects drain when app was provisioned at a previous generation", Label(unitLabel), func() {
		ns := "default"
		appName := "updated-app"

		app := NewBrokerApp(appName, ns).
			WithAddresses(NewAddressType("orders").Build()).
			Build()

		reconciler := BrokerServiceInstanceReconcilerForTestWithInstance(ns, "test-service")
		app.Generation = 1
		provisionedIdentity := AppIdentityWithGeneration(app)
		app.Generation = 3

		reconciler.status.ProvisionedApps = []string{provisionedIdentity}

		oldSecretData := buildOldSecretData(app, "orders")
		emptyTracker := newAddressTracker()

		// Jolokia is unavailable so all candidates are preserved as draining
		result := reconciler.detectDrainingAddresses(app, emptyTracker, oldSecretData)
		Expect(result).NotTo(BeNil(), "should detect drain when app was provisioned at any prior generation")
	})

	It("should not add consume permission for producer-only address during drain", Label(unitLabel), func() {
		ns := "default"
		appName := "producer-app"

		app := NewBrokerApp(appName, ns).
			WithProducerOf(NewAddressRef("notifications").Build()).
			WithProducerOf(NewAddressRef("orders").Build()).
			WithConsumerOf(NewAddressRef("orders").Build()).
			Build()

		reconciler := BrokerServiceInstanceReconcilerForTestWithInstance(ns, "test-service")
		reconciler.status.ProvisionedApps = []string{
			AppIdentityWithGeneration(app),
		}
		Expect(reconciler.Client.Create(context.TODO(), app)).To(Succeed())

		// Old secret has both addresses configured with producer-only roles for notifications
		oldCaps := &brokerproperties.CapabilitiesJSON{
			AddressConfigurations: map[string]*brokerproperties.AddressConfiguration{
				"notifications": {RoutingTypes: brokerproperties.RoutingTypeAnycast},
				"orders":        {RoutingTypes: brokerproperties.RoutingTypeAnycast},
			},
			SecurityRoles: map[string]map[string]*brokerproperties.RolePermissions{
				"notifications": {
					producerRole(AppIdentity(app)): {Send: true},
				},
				"orders": {
					producerRole(AppIdentity(app)): {Send: true},
					consumerRole(AppIdentity(app)): {Consume: true},
				},
			},
		}
		oldData, err := json.Marshal(oldCaps)
		Expect(err).NotTo(HaveOccurred())
		capKey := AppIdentityPrefixed(app, "capabilities.json")
		oldSecretData := map[string][]byte{capKey: oldData}

		// Current spec: notifications removed, orders remains
		app.Spec.Capabilities = []v1beta2.AppCapabilityType{
			{
				ProducerOf: []v1beta2.AddressRef{{Address: "orders"}},
				ConsumerOf: []v1beta2.AddressRef{{Address: "orders"}},
			},
		}

		tracker, buildErr := reconciler.buildAddressTracker(app)
		Expect(buildErr).NotTo(HaveOccurred())

		skip, drainErr := reconciler.processDrain(app, tracker, oldSecretData)
		Expect(drainErr).NotTo(HaveOccurred())
		Expect(skip).To(BeFalse())

		// Generate capabilities from the tracker
		secret := &corev1.Secret{}
		secret.Data = make(map[string][]byte)
		Expect(reconciler.processCapabilities(secret, app, tracker)).To(Succeed())

		var caps brokerproperties.CapabilitiesJSON
		Expect(json.Unmarshal(secret.Data[capKey], &caps)).To(Succeed())

		// notifications should be preserved during drain but should NOT have consume permission
		Expect(caps.AddressConfigurations).Should(HaveKey("notifications"),
			"draining address should be preserved in config")
		if notifRoles, ok := caps.SecurityRoles["notifications"]; ok {
			for roleName, perms := range notifRoles {
				Expect(perms.Consume).Should(BeFalse(),
					"producer-only address should not gain consume permission during drain, role: %s", roleName)
			}
		}

		// orders should retain both send and consume
		Expect(caps.SecurityRoles).Should(HaveKey("orders"))
		hasSend := false
		hasConsume := false
		for _, perms := range caps.SecurityRoles["orders"] {
			if perms.Send {
				hasSend = true
			}
			if perms.Consume {
				hasConsume = true
			}
		}
		Expect(hasSend).Should(BeTrue(), "orders should retain send permission")
		Expect(hasConsume).Should(BeTrue(), "orders should retain consume permission")
	})

	It("does not flag address that is still in the current spec", Label(unitLabel), func() {
		ns := "default"
		appName := "retained-app"

		app := NewBrokerApp(appName, ns).
			WithAddresses(NewAddressType("orders").Build()).
			Build()

		reconciler := BrokerServiceInstanceReconcilerForTestWithInstance(ns, "test-service")
		reconciler.status.ProvisionedApps = []string{
			AppIdentityWithGeneration(app),
		}

		oldSecretData := buildOldSecretData(app, "orders", "notifications")

		tracker, err := reconciler.buildAddressTracker(app)
		Expect(err).NotTo(HaveOccurred())

		result := reconciler.detectDrainingAddresses(app, tracker, oldSecretData)
		Expect(result).To(HaveLen(1), "only removed address should be flagged")
		Expect(result[0].Address).To(Equal("notifications"))
	})

	It("extracts subscription queues from multicast address old config", Label(unitLabel), func() {
		ns := "default"
		appName := "multicast-app"

		app := NewBrokerApp(appName, ns).Build()

		reconciler := BrokerServiceInstanceReconcilerForTestWithInstance(ns, "test-service")
		reconciler.status.ProvisionedApps = []string{
			AppIdentityWithGeneration(app),
		}

		oldCaps := &brokerproperties.CapabilitiesJSON{
			AddressConfigurations: map[string]*brokerproperties.AddressConfiguration{
				"events": {
					RoutingTypes: brokerproperties.RoutingTypeMulticast,
					QueueConfigs: map[string]*brokerproperties.QueueConfig{
						"client-a.events": {RoutingType: brokerproperties.RoutingTypeMulticast, Address: "events"},
						"client-b.events": {RoutingType: brokerproperties.RoutingTypeMulticast, Address: "events"},
					},
				},
			},
		}
		data, err := json.Marshal(oldCaps)
		Expect(err).NotTo(HaveOccurred())
		capKey := AppIdentityPrefixed(app, "capabilities.json")
		oldSecretData := map[string][]byte{capKey: data}

		emptyTracker := newAddressTracker()

		result := reconciler.detectDrainingAddresses(app, emptyTracker, oldSecretData)
		Expect(result).To(HaveLen(1))
		Expect(result[0].Address).To(Equal("events"))
		Expect(result[0].Subscriptions).To(ConsistOf("client-a.events", "client-b.events"))
	})
})

var _ = Describe("evaluateAddressDrainStatus unit", func() {

	var (
		mockCtrl *gomock.Controller
		logger   = logf.Log.WithName("drain-test")
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
	})
	AfterEach(func() {
		mockCtrl.Finish()
	})

	mockArtemisWithQueues := func(queues []mgmt.QueueMessageCount) *mgmt.Artemis {
		j := jolokia.NewMockIJolokia(mockCtrl)
		j.EXPECT().ReadMap(gomock.Any()).Return(
			buildMockQueueCountResponse(queues), nil,
		)
		return mgmt.GetArtemisWithJolokia(j, "test-broker")
	}

	It("marks anycast address as undrained when queue has messages", Label(unitLabel), func() {
		artemis := mockArtemisWithQueues([]mgmt.QueueMessageCount{
			{Address: "orders", Queue: "orders", RoutingType: "anycast", Count: 10},
		})
		addresses := []DrainingAddressInfo{{Address: "orders"}}

		result := evaluateAddressDrainStatus(logger, artemis, addresses)
		Expect(result).To(HaveKey("orders"))
		Expect(result["orders"].drained).To(BeFalse())
		Expect(result["orders"].messageCounts["orders"]).To(Equal(int64(10)))
	})

	It("marks anycast address as drained when queue has zero messages", Label(unitLabel), func() {
		artemis := mockArtemisWithQueues([]mgmt.QueueMessageCount{
			{Address: "orders", Queue: "orders", RoutingType: "anycast", Count: 0},
		})
		addresses := []DrainingAddressInfo{{Address: "orders"}}

		result := evaluateAddressDrainStatus(logger, artemis, addresses)
		Expect(result["orders"].drained).To(BeTrue())
	})

	It("marks address as drained when its queue is absent but other queues exist", Label(unitLabel), func() {
		artemis := mockArtemisWithQueues([]mgmt.QueueMessageCount{
			{Address: "other", Queue: "other", RoutingType: "anycast", Count: 0},
		})
		addresses := []DrainingAddressInfo{{Address: "orders"}}

		result := evaluateAddressDrainStatus(logger, artemis, addresses)
		Expect(result["orders"].drained).To(BeTrue())
	})

	It("marks multicast address as undrained when any subscription has messages", Label(unitLabel), func() {
		artemis := mockArtemisWithQueues([]mgmt.QueueMessageCount{
			{Address: "events", Queue: "client-a.events", RoutingType: "multicast", Count: 0},
			{Address: "events", Queue: "client-b.events", RoutingType: "multicast", Count: 5},
		})
		addresses := []DrainingAddressInfo{
			{Address: "events", Subscriptions: []string{"client-a.events", "client-b.events"}},
		}

		result := evaluateAddressDrainStatus(logger, artemis, addresses)
		Expect(result["events"].drained).To(BeFalse())
		Expect(result["events"].messageCounts["events::client-b.events"]).To(Equal(int64(5)))
	})

	It("marks multicast address as drained when all subscriptions are empty", Label(unitLabel), func() {
		artemis := mockArtemisWithQueues([]mgmt.QueueMessageCount{
			{Address: "events", Queue: "client-a.events", RoutingType: "multicast", Count: 0},
			{Address: "events", Queue: "client-b.events", RoutingType: "multicast", Count: 0},
		})
		addresses := []DrainingAddressInfo{
			{Address: "events", Subscriptions: []string{"client-a.events", "client-b.events"}},
		}

		result := evaluateAddressDrainStatus(logger, artemis, addresses)
		Expect(result["events"].drained).To(BeTrue())
	})

	It("marks all addresses as undrained when Jolokia fails", Label(unitLabel), func() {
		j := jolokia.NewMockIJolokia(mockCtrl)
		j.EXPECT().ReadMap(gomock.Any()).Return(nil, fmt.Errorf("connection refused"))
		artemis := mgmt.GetArtemisWithJolokia(j, "test-broker")

		addresses := []DrainingAddressInfo{{Address: "orders"}}

		result := evaluateAddressDrainStatus(logger, artemis, addresses)
		Expect(result["orders"].drained).To(BeFalse())
	})
})
