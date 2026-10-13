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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"github.com/Azure/go-amqp"
	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	broker "github.com/arkmq-org/arkmq-org-broker-operator/v2/api/v1beta2"
	brokerproperties "github.com/arkmq-org/arkmq-org-broker-operator/v2/pkg/brokerproperties"
	"github.com/arkmq-org/arkmq-org-broker-operator/v2/pkg/resources/ingresses"
	"github.com/arkmq-org/arkmq-org-broker-operator/v2/pkg/resources/secrets"
	svc "github.com/arkmq-org/arkmq-org-broker-operator/v2/pkg/resources/services"
	"github.com/arkmq-org/arkmq-org-broker-operator/v2/pkg/utils/common"
	"github.com/arkmq-org/arkmq-org-broker-operator/v2/pkg/utils/selectors"
)

var _ = Describe("broker-service address drain on removal", func() {

	BeforeEach(func() {
		BeforeEachSpec()

		if verbose {
			fmt.Println("Time with MicroSeconds: ", time.Now().Format("2006-01-02 15:04:05.000000"), " test:", CurrentSpecReport())
		}

		if os.Getenv("USE_EXISTING_CLUSTER") == "true" {
			if !CertManagerInstalled() {
				Expect(InstallCertManager()).To(Succeed())
			}

			rootIssuer = InstallClusteredIssuer(rootIssuerName, nil)

			rootCert = InstallCert(rootCertName, rootCertNamespce, func(candidate *cmv1.Certificate) {
				candidate.Spec.IsCA = true
				candidate.Spec.CommonName = "artemis.root.ca"
				candidate.Spec.SecretName = rootCertSecretName
				candidate.Spec.IssuerRef = cmmetav1.ObjectReference{
					Name: rootIssuer.Name,
					Kind: "ClusterIssuer",
				}
			})

			caIssuer = InstallClusteredIssuer(caIssuerName, func(candidate *cmv1.ClusterIssuer) {
				candidate.Spec.SelfSigned = nil
				candidate.Spec.CA = &cmv1.CAIssuer{
					SecretName: rootCertSecretName,
				}
			})
			InstallCaBundle(common.DefaultOperatorCASecretName, rootCertSecretName, caPemTrustStoreName)

			By("installing operator cert")
			InstallCert(common.DefaultOperatorCertSecretName, defaultNamespace, func(candidate *cmv1.Certificate) {
				candidate.Spec.SecretName = common.DefaultOperatorCertSecretName
				candidate.Spec.CommonName = common.OperatorName
				candidate.Spec.IssuerRef = cmmetav1.ObjectReference{
					Name: caIssuer.Name,
					Kind: "ClusterIssuer",
				}
			})
		}
	})

	AfterEach(func() {
		AfterEachSpec()
	})

	// helper: create a BrokerService with certs and wait for it to exist
	setupService := func(ctx context.Context, serviceName string, selectorLabels map[string]string) broker.BrokerService {
		sharedOperandCertName := serviceName + "-" + common.DefaultOperandCertSecretName
		InstallCert(sharedOperandCertName, defaultNamespace, func(candidate *cmv1.Certificate) {
			candidate.Spec.SecretName = sharedOperandCertName
			candidate.Spec.CommonName = serviceName
			candidate.Spec.DNSNames = []string{
				serviceName,
				fmt.Sprintf("%s.%s", serviceName, defaultNamespace),
				fmt.Sprintf("%s.%s.svc.%s", serviceName, defaultNamespace, common.GetClusterDomain()),
				common.ClusterDNSWildCard(serviceName, defaultNamespace),
			}
			candidate.Spec.IssuerRef = cmmetav1.ObjectReference{
				Name: caIssuer.Name,
				Kind: "ClusterIssuer",
			}
		})

		prometheusCertName := common.DefaultPrometheusCertSecretName
		InstallCert(prometheusCertName, defaultNamespace, func(candidate *cmv1.Certificate) {
			candidate.Spec.SecretName = prometheusCertName
			candidate.Spec.CommonName = "prometheus"
			candidate.Spec.IssuerRef = cmmetav1.ObjectReference{
				Name: caIssuer.Name,
				Kind: "ClusterIssuer",
			}
		})

		service := broker.BrokerService{
			TypeMeta: metav1.TypeMeta{
				Kind:       "BrokerService",
				APIVersion: broker.GroupVersion.Identifier(),
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      serviceName,
				Namespace: defaultNamespace,
				Labels:    selectorLabels,
			},
			Spec: broker.BrokerServiceSpec{
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse("2Gi"),
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, &service)).Should(Succeed())
		return service
	}

	// helper: create a BrokerApp with certs
	setupApp := func(ctx context.Context, appName string, selectorLabels map[string]string, spec broker.BrokerAppSpec) broker.BrokerApp {
		InstallCert(appName+"-"+common.DefaultOperandCertSecretName, defaultNamespace, func(candidate *cmv1.Certificate) {
			candidate.Spec.SecretName = appName + "-" + common.DefaultOperandCertSecretName
			candidate.Spec.CommonName = appName
			candidate.Spec.IssuerRef = cmmetav1.ObjectReference{
				Name: caIssuer.Name,
				Kind: "ClusterIssuer",
			}
		})

		spec.ServiceSelector = &metav1.LabelSelector{
			MatchLabels: selectorLabels,
		}
		if spec.Resources.Requests == nil {
			spec.Resources = corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceMemory: resource.MustParse("256Mi"),
				},
			}
		}

		app := broker.BrokerApp{
			TypeMeta: metav1.TypeMeta{
				Kind:       "BrokerApp",
				APIVersion: broker.GroupVersion.Identifier(),
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      appName,
				Namespace: defaultNamespace,
			},
			Spec: spec,
		}
		InstallAppCert(&app)
		Expect(k8sClient.Create(ctx, &app)).Should(Succeed())

		createdApp := &broker.BrokerApp{}
		Eventually(func(g Gomega) {

			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: app.Name, Namespace: defaultNamespace}, createdApp)).Should(Succeed())

			if verbose {
				fmt.Printf("\nCREATED APP: %v\n", createdApp.Status)
			}

			readyCond := meta.FindStatusCondition(createdApp.Status.Conditions, broker.ReadyConditionType)

			g.Expect(readyCond).ToNot(BeNil())
			g.Expect(readyCond.Status).To(Equal(metav1.ConditionTrue))

			if verbose {
				fmt.Printf("\nAPP Finalizers: %v\n", createdApp.ObjectMeta.Finalizers)
			}

		}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

		return app
	}

	// helper: verify app is provisioned on the service
	verifyProvisioned := func(ctx context.Context, serviceName, appName string) {
		createdService := &broker.BrokerService{}
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: defaultNamespace}, createdService)).Should(Succeed())

			if verbose {
				fmt.Printf("\nPROVISIONED STATUS: %v\n", createdService.Status)
				fmt.Printf("\nPROVISIONED Finalizers: %v\n", createdService.ObjectMeta.Finalizers)
			}

			g.Expect(createdService.Status.ProvisionedApps).Should(ContainElement(ContainSubstring(appName)))
		}, existingClusterTimeout, existingClusterInterval).Should(Succeed())
	}

	// helper: verify app-props secret contains capabilities for an app
	verifyCapabilitiesPresent := func(ctx context.Context, serviceName string, app *broker.BrokerApp) {
		secretName := AppPropertiesSecretName(serviceName)
		configKey := AppIdentityPrefixed(app, "capabilities.json")
		secret := &corev1.Secret{}
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())
			_, found := secret.Data[configKey]
			g.Expect(found).Should(BeTrue(), "capabilities config for %s should be in secret", app.Name)
		}, existingClusterTimeout, existingClusterInterval).Should(Succeed())
	}

	// helper: verify app-props secret no longer contains capabilities for an app
	verifyCapabilitiesRemoved := func(ctx context.Context, serviceName string, app *broker.BrokerApp) {
		secretName := AppPropertiesSecretName(serviceName)
		configKey := AppIdentityPrefixed(app, "capabilities.json")
		secret := &corev1.Secret{}
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())
			_, found := secret.Data[configKey]
			g.Expect(found).Should(BeFalse(), "capabilities config for %s should have been removed from secret", app.Name)
		}, existingClusterTimeout, existingClusterInterval).Should(Succeed())
	}

	type mqttTestEndpoint struct {
		tlsConfig *tls.Config
		serverURL *url.URL
		accSvc    *corev1.Service
		accIng    *netv1.Ingress
	}

	// helper: set up service, ingress, and TLS for MQTT access to an app's acceptor
	setupMqttEndpoint := func(ctx context.Context, serviceName, appName string) mqttTestEndpoint {
		createdApp := &broker.BrokerApp{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, createdApp)).Should(Succeed())
		Expect(createdApp.Status.Service).ShouldNot(BeNil())
		appPort := createdApp.Status.Service.AssignedPort
		Expect(appPort).ShouldNot(BeZero())

		accServiceName := appName + "-acc-drain"
		accService := svc.NewServiceDefinitionForCR(
			types.NamespacedName{Namespace: defaultNamespace, Name: accServiceName},
			k8sClient, "acc-port", appPort,
			map[string]string{selectors.LabelAppKubernetesInstance: serviceName}, nil, nil)
		Expect(k8sClient.Create(ctx, accService)).Should(Succeed())

		acceptorIngressHost := accServiceName + "-" + defaultNamespace + "." + defaultTestIngressDomain
		accIngress := ingresses.NewIngressForCRWithSSL(nil,
			types.NamespacedName{Namespace: defaultNamespace, Name: accServiceName},
			nil, accServiceName, fmt.Sprintf("%d", appPort), true,
			defaultTestIngressDomain, acceptorIngressHost, isOpenshift)
		Expect(k8sClient.Create(ctx, accIngress)).Should(Succeed())

		operandCertName := serviceName + "-" + common.DefaultOperandCertSecretName
		operandSecret, err := secrets.RetriveSecret(
			types.NamespacedName{Namespace: defaultNamespace, Name: operandCertName},
			make(map[string]string), k8sClient)
		Expect(err).Should(BeNil())
		certpool := x509.NewCertPool()
		certpool.AppendCertsFromPEM(operandSecret.Data["tls.crt"])

		appCertName := appName + common.AppCertSecretSuffix
		appCertSecret, err := secrets.RetriveSecret(
			types.NamespacedName{Namespace: defaultNamespace, Name: appCertName},
			make(map[string]string), k8sClient)
		Expect(err).Should(BeNil())
		clientKeyPair, err := tls.X509KeyPair(appCertSecret.Data["tls.crt"], appCertSecret.Data["tls.key"])
		Expect(err).Should(BeNil())

		serverURL, err := url.Parse("ssl://" + clusterIngressHost + ":443")
		Expect(err).Should(BeNil())

		return mqttTestEndpoint{
			tlsConfig: &tls.Config{
				RootCAs:            certpool,
				Certificates:       []tls.Certificate{clientKeyPair},
				ServerName:         acceptorIngressHost,
				InsecureSkipVerify: true,
			},
			serverURL: serverURL,
			accSvc:    accService,
			accIng:    accIngress,
		}
	}

	// helper: establish a durable MQTT subscription then disconnect
	mqttSubscribe := func(ctx context.Context, ep mqttTestEndpoint, clientID, topic string) {
		Eventually(func(g Gomega) {
			conn, err := autopaho.NewConnection(ctx, autopaho.ClientConfig{
				ServerUrls: []*url.URL{ep.serverURL},
				TlsCfg:     ep.tlsConfig,
				KeepAlive:  30,
				ClientConfig: paho.ClientConfig{
					ClientID: clientID,
				},
			})
			g.Expect(err).Should(BeNil())

			connCtx, connCancel := context.WithTimeout(ctx, 30*time.Second)
			defer connCancel()
			g.Expect(conn.AwaitConnection(connCtx)).Should(Succeed())

			_, err = conn.Subscribe(ctx, &paho.Subscribe{
				Subscriptions: []paho.SubscribeOptions{
					{Topic: topic, QoS: 1},
				},
			})
			g.Expect(err).Should(BeNil())

			g.Expect(conn.Disconnect(ctx)).Should(Succeed())
		}, existingClusterTimeout, existingClusterInterval).Should(Succeed())
	}

	// helper: publish messages via MQTT, retries until the broker has reloaded config
	mqttProduce := func(ctx context.Context, ep mqttTestEndpoint, topic string, count int) {
		Eventually(func(g Gomega) {
			conn, err := autopaho.NewConnection(ctx, autopaho.ClientConfig{
				ServerUrls: []*url.URL{ep.serverURL},
				TlsCfg:     ep.tlsConfig,
				KeepAlive:  30,
				ClientConfig: paho.ClientConfig{
					ClientID: "drain-test-producer",
				},
			})
			g.Expect(err).Should(BeNil())

			connCtx, connCancel := context.WithTimeout(ctx, 30*time.Second)
			defer connCancel()
			g.Expect(conn.AwaitConnection(connCtx)).Should(Succeed())

			for i := 0; i < count; i++ {
				_, err = conn.Publish(ctx, &paho.Publish{
					Topic:   topic,
					QoS:     1,
					Payload: []byte(fmt.Sprintf("drain-test-%s-%d", topic, i)),
				})
				g.Expect(err).Should(BeNil())
			}

			g.Expect(conn.Disconnect(ctx)).Should(Succeed())
		}, existingClusterTimeout, existingClusterInterval).Should(Succeed())
	}

	// helper: consume messages via MQTT durable subscription
	mqttConsume := func(ctx context.Context, ep mqttTestEndpoint, clientID, topic string, expectedMin int) {
		var consumed int32
		Eventually(func(g Gomega) {
			atomic.StoreInt32(&consumed, 0)
			router := paho.NewStandardRouter()
			router.RegisterHandler(topic, func(p *paho.Publish) {
				atomic.AddInt32(&consumed, 1)
				if verbose {
					fmt.Printf("Consumed message: '%s'\n", p.Payload)
				}
			})

			conn, err := autopaho.NewConnection(ctx, autopaho.ClientConfig{
				ServerUrls: []*url.URL{ep.serverURL},
				TlsCfg:     ep.tlsConfig,
				KeepAlive:  30,
				ClientConfig: paho.ClientConfig{
					ClientID: clientID,
					Router:   router,
				},
			})
			g.Expect(err).Should(BeNil())

			connCtx, connCancel := context.WithTimeout(ctx, 30*time.Second)
			defer connCancel()
			g.Expect(conn.AwaitConnection(connCtx)).Should(Succeed())

			_, err = conn.Subscribe(ctx, &paho.Subscribe{
				Subscriptions: []paho.SubscribeOptions{
					{Topic: topic, QoS: 1},
				},
			})
			g.Expect(err).Should(BeNil())

			time.Sleep(10 * time.Second)

			g.Expect(conn.Disconnect(ctx)).Should(Succeed())
			g.Expect(atomic.LoadInt32(&consumed)).Should(BeNumerically(">=", int32(expectedMin)),
				"should have consumed all produced messages")
		}, existingClusterTimeout, existingClusterInterval).Should(Succeed())
	}

	// helper: clean up MQTT endpoint resources
	cleanupMqttEndpoint := func(ep mqttTestEndpoint) {
		Expect(k8sClient.Delete(ctx, ep.accIng)).Should(Succeed())
		Expect(k8sClient.Delete(ctx, ep.accSvc)).Should(Succeed())
	}

	amqpDialSASLExternal := func(g Gomega, ctx context.Context, ep mqttTestEndpoint, containerID string) *amqp.Conn {

		url := "amqps://" + clusterIngressHost + ":443"
		conn, err := amqp.Dial(ctx, url, &amqp.ConnOptions{
			ContainerID: containerID,
			SASLType:    amqp.SASLTypeExternal(""),
			TLSConfig:   ep.tlsConfig,
		})
		g.Expect(err).ShouldNot(HaveOccurred())
		return conn
	}

	// helper: produce messages to an anycast address via AMQP
	amqpProduce := func(ctx context.Context, ep mqttTestEndpoint, address string, count int) {
		Eventually(func(g Gomega) {
			conn := amqpDialSASLExternal(g, ctx, ep, "drain-amqp-producer")
			defer func() {
				_ = conn.Close()
			}()
			session, err := conn.NewSession(ctx, nil)
			g.Expect(err).ShouldNot(HaveOccurred())

			sender, err := session.NewSender(ctx, address, nil)
			g.Expect(err).ShouldNot(HaveOccurred())

			sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			defer func() {
				_ = sender.Close(sendCtx)
			}()

			for i := 0; i < count; i++ {
				err = sender.Send(sendCtx, amqp.NewMessage([]byte(fmt.Sprintf("drain-test-%s-%d", address, i))), nil)
				g.Expect(err).ShouldNot(HaveOccurred())
			}
		}, existingClusterTimeout, existingClusterInterval).Should(Succeed())
	}

	// helper: consume messages from an anycast address via AMQP
	amqpConsume := func(ctx context.Context, ep mqttTestEndpoint, address string, expectedCount int) {
		Eventually(func(g Gomega) {
			conn := amqpDialSASLExternal(g, ctx, ep, "drain-amqp-consumer")
			defer func() {
				_ = conn.Close()
			}()
			session, err := conn.NewSession(ctx, nil)
			g.Expect(err).ShouldNot(HaveOccurred())

			receiver, err := session.NewReceiver(ctx, address, &amqp.ReceiverOptions{
				Credit: int32(expectedCount + 1),
			})
			g.Expect(err).ShouldNot(HaveOccurred())

			recvCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			defer func() {
				_ = receiver.Close(recvCtx)
			}()
			for i := 0; i < expectedCount; i++ {
				msg, err := receiver.Receive(recvCtx, nil)
				g.Expect(err).ShouldNot(HaveOccurred())
				g.Expect(receiver.AcceptMessage(recvCtx, msg)).Should(Succeed())
			}
		}, existingClusterTimeout, existingClusterInterval).Should(Succeed())
	}

	Context("app deletion should drain addresses before removal", func() {

		It("should preserve address config in app-props secret until queues are drained", func() {

			if os.Getenv("USE_EXISTING_CLUSTER") != "true" {
				return
			}

			ctx := context.Background()
			serviceName := NextSpecResourceName()
			labels := map[string]string{"test": "drain-delete"}

			By("creating service")
			service := setupService(ctx, serviceName, labels)

			By("creating app with address 'orders'")
			appName := NextSpecResourceName()
			drainClientID := "drain-client"
			drainSubName := drainClientID + ".orders"
			app := setupApp(ctx, appName, labels, broker.BrokerAppSpec{
				Capabilities: []broker.AppCapabilityType{
					{
						ProducerOf: []broker.AddressRef{{Address: "orders"}},
						ConsumerOf: []broker.AddressRef{{
							Address:       "orders",
							Subscriptions: []string{drainSubName},
						}},
					},
				},
			})

			By("verifying app is provisioned")
			verifyProvisioned(ctx, serviceName, appName)

			By("verifying capabilities config is in the app-props secret with producer role")
			secretName := AppPropertiesSecretName(serviceName)
			configKey := AppIdentityPrefixed(&app, "capabilities.json")
			Eventually(func(g Gomega) {
				secret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())
				capData, found := secret.Data[configKey]
				g.Expect(found).Should(BeTrue(), "capabilities config should be in secret")
				g.Expect(string(capData)).Should(ContainSubstring(`"send":true`))
				g.Expect(string(capData)).Should(ContainSubstring(`"consume":true`))
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("setting up MQTT endpoint for messaging")
			ep := setupMqttEndpoint(ctx, serviceName, appName)

			By("establishing durable subscription before producing")
			mqttSubscribe(ctx, ep, drainClientID, "orders")

			By("producing messages to 'orders' via MQTT to ensure drain has work to do")
			messageCount := 5
			mqttProduce(ctx, ep, "orders", messageCount)

			By("deleting the app")
			Expect(k8sClient.Delete(ctx, &app)).Should(Succeed())

			By("verifying app is retained by drain finalizer with draining status")
			Eventually(func(g Gomega) {
				drainApp := &broker.BrokerApp{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, drainApp)).Should(Succeed())

				if verbose {
					fmt.Printf("\nRETAINED APP: %v\n", drainApp)
				}
				g.Expect(drainApp.DeletionTimestamp).ShouldNot(BeNil())
				g.Expect(drainApp.Finalizers).Should(ContainElement(BrokerAppDrainFinalizer))

				readyCond := meta.FindStatusCondition(drainApp.Status.Conditions, broker.ReadyConditionType)
				g.Expect(readyCond).ShouldNot(BeNil())
				g.Expect(readyCond.Status).Should(Equal(metav1.ConditionFalse))
				g.Expect(readyCond.Reason).Should(Equal(broker.ReadyConditionUnbindingReason))
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("verifying producer role is dropped from capabilities during drain")
			Eventually(func(g Gomega) {
				secret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())
				capData, found := secret.Data[configKey]
				g.Expect(found).Should(BeTrue(), "capabilities config should be preserved during drain")
				g.Expect(string(capData)).ShouldNot(ContainSubstring(`"send":true`), "producer role should be dropped during drain")
				g.Expect(string(capData)).Should(ContainSubstring(`"consume":true`), "consumer role should remain during drain")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("verifying service status reports draining addresses with message counts")
			Eventually(func(g Gomega) {
				svc := &broker.BrokerService{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: defaultNamespace}, svc)).Should(Succeed())
				g.Expect(svc.Status.Draining).ShouldNot(BeEmpty(), "service status should report draining entries")
				g.Expect(svc.Status.Draining[0].App).Should(Equal(AppIdentity(&app)))
				g.Expect(svc.Status.Draining[0].Messages).ShouldNot(BeEmpty(), "draining entry should include message counts")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("consuming messages via MQTT to allow drain to complete")
			mqttConsume(ctx, ep, drainClientID, "orders", messageCount)

			By("verifying app is eventually deleted after drain completes")
			Eventually(func() bool {
				return errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, &broker.BrokerApp{}))
			}, existingClusterTimeout, existingClusterInterval).Should(BeTrue())

			By("verifying capabilities are removed from secret after drain completion")
			verifyCapabilitiesRemoved(ctx, serviceName, &app)

			By("verifying service draining status is cleared after drain completes")
			Eventually(func(g Gomega) {
				svc := &broker.BrokerService{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: defaultNamespace}, svc)).Should(Succeed())
				g.Expect(svc.Status.Draining).Should(BeEmpty(), "draining status should be cleared after drain completes")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("cleanup")
			cleanupMqttEndpoint(ep)
			Expect(k8sClient.Delete(ctx, &service)).Should(Succeed())
			UninstallCert(appName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(serviceName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(common.DefaultPrometheusCertSecretName, defaultNamespace)
		})
	})

	Context("app selector change should drain addresses before unbinding", func() {

		It("should preserve non empty address config when app no longer matches service selector", func() {

			if os.Getenv("USE_EXISTING_CLUSTER") != "true" {
				return
			}

			ctx := context.Background()
			serviceName := NextSpecResourceName()
			labels := map[string]string{"test": "drain-unbind"}

			By("creating service")
			service := setupService(ctx, serviceName, labels)

			By("creating app matching the service")
			appName := NextSpecResourceName()
			drainClientID := "drain-client"
			drainSubName := drainClientID + ".events"
			app := setupApp(ctx, appName, labels, broker.BrokerAppSpec{
				Capabilities: []broker.AppCapabilityType{
					{
						ProducerOf: []broker.AddressRef{{Address: "events"}},
						ConsumerOf: []broker.AddressRef{{
							Address:       "events",
							Subscriptions: []string{drainSubName},
						}},
					},
				},
			})

			By("verifying app is provisioned")
			verifyProvisioned(ctx, serviceName, appName)
			verifyCapabilitiesPresent(ctx, serviceName, &app)

			By("setting up MQTT endpoint for messaging")
			ep := setupMqttEndpoint(ctx, serviceName, appName)

			By("establishing durable subscription before producing")
			mqttSubscribe(ctx, ep, drainClientID, "events")

			By("producing messages to 'events' via MQTT to ensure drain has work to do")
			messageCount := 5
			mqttProduce(ctx, ep, "events", messageCount)

			By("changing app's service selector so it no longer matches")
			updatedApp := &broker.BrokerApp{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, updatedApp)).Should(Succeed())
			updatedApp.Spec.ServiceSelector = &metav1.LabelSelector{
				MatchLabels: map[string]string{"test": "no-such-service"},
			}
			Expect(k8sClient.Update(ctx, updatedApp)).Should(Succeed())

			By("verifying app enters draining state")
			Eventually(func(g Gomega) {
				drainApp := &broker.BrokerApp{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, drainApp)).Should(Succeed())

				if verbose {
					fmt.Printf("\n DRAINING APP STATUS: %v\n", drainApp.Status)
				}

				readyCond := meta.FindStatusCondition(drainApp.Status.Conditions, broker.ReadyConditionType)
				g.Expect(readyCond).ShouldNot(BeNil())
				g.Expect(readyCond.Status).Should(Equal(metav1.ConditionFalse))
				g.Expect(readyCond.Reason).Should(Equal(broker.ReadyConditionUnbindingReason))
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("verifying address config is preserved during drain with producer role dropped")
			secretName := AppPropertiesSecretName(serviceName)
			configKey := AppIdentityPrefixed(&app, "capabilities.json")
			Eventually(func(g Gomega) {
				secret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())
				capData, found := secret.Data[configKey]
				g.Expect(found).Should(BeTrue(), "capabilities config should be preserved during drain")
				g.Expect(string(capData)).ShouldNot(ContainSubstring(`"send":true`), "producer role should be dropped during drain")
				g.Expect(string(capData)).Should(ContainSubstring(`"consume":true`), "consumer role should remain during drain")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("consuming messages via MQTT to allow drain to complete")
			mqttConsume(ctx, ep, drainClientID, "events", messageCount)

			By("verifying app is unbound after drain completes")
			Eventually(func(g Gomega) {
				drainApp := &broker.BrokerApp{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, drainApp)).Should(Succeed())
				g.Expect(drainApp.Status.Service).Should(BeNil(), "app should be unbound after drain")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("verifying capabilities are removed after drain completes")
			verifyCapabilitiesRemoved(ctx, serviceName, &app)

			By("cleanup")
			cleanupMqttEndpoint(ep)
			Expect(k8sClient.Delete(ctx, updatedApp)).Should(Succeed())
			Eventually(func() bool {
				return errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, &broker.BrokerApp{}))
			}, existingClusterTimeout, existingClusterInterval).Should(BeTrue())
			Expect(k8sClient.Delete(ctx, &service)).Should(Succeed())
			UninstallCert(appName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(serviceName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(common.DefaultPrometheusCertSecretName, defaultNamespace)
		})
	})

	Context("address removal from app should drain before removing config", func() {

		It("should preserve removed address config while keeping remaining addresses active", func() {

			if os.Getenv("USE_EXISTING_CLUSTER") != "true" {
				return
			}

			ctx := context.Background()
			serviceName := NextSpecResourceName()
			labels := map[string]string{"test": "drain-addr-remove"}

			By("creating service")
			service := setupService(ctx, serviceName, labels)

			By("creating app with two addresses: 'orders' and 'events'")
			appName := NextSpecResourceName()
			drainClientID := "drain-client"
			drainEventsSubName := drainClientID + ".events"
			drainOrdersSubName := drainClientID + ".orders"

			app := setupApp(ctx, appName, labels, broker.BrokerAppSpec{
				Capabilities: []broker.AppCapabilityType{
					{
						ProducerOf: []broker.AddressRef{
							{Address: "orders"},
							{Address: "events"},
						},
						ConsumerOf: []broker.AddressRef{
							{
								Address:       "orders",
								Subscriptions: []string{drainOrdersSubName},
							},
							{
								Address:       "events",
								Subscriptions: []string{drainEventsSubName},
							},
						},
					},
				},
			})

			By("verifying app is provisioned with both addresses")
			verifyProvisioned(ctx, serviceName, appName)
			verifyCapabilitiesPresent(ctx, serviceName, &app)

			secretName := AppPropertiesSecretName(serviceName)
			configKey := AppIdentityPrefixed(&app, "capabilities.json")
			Eventually(func(g Gomega) {
				secret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())
				g.Expect(string(secret.Data[configKey])).Should(ContainSubstring("orders"))
				g.Expect(string(secret.Data[configKey])).Should(ContainSubstring("events"))
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("setting up MQTT endpoint for messaging")
			ep := setupMqttEndpoint(ctx, serviceName, appName)

			By("establishing durable subscription to 'events' before producing")
			mqttSubscribe(ctx, ep, drainClientID, "events")

			By("producing messages to 'events' via MQTT to ensure drain has work to do")
			messageCount := 5
			mqttProduce(ctx, ep, "events", messageCount)

			By("verifying capabilities.json includes both addresses before spec change")
			Eventually(func(g Gomega) {
				secret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())
				capData := secret.Data[configKey]
				g.Expect(capData).ShouldNot(BeEmpty())

				var caps brokerproperties.CapabilitiesJSON
				g.Expect(json.Unmarshal(capData, &caps)).Should(Succeed())
				g.Expect(caps.AddressConfigurations).Should(HaveKey("orders"), "orders should be configured before spec change")
				g.Expect(caps.AddressConfigurations).Should(HaveKey("events"), "events should be configured before spec change")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("removing 'events' address from the app, keeping 'orders'")
			updatedApp := &broker.BrokerApp{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, updatedApp)).Should(Succeed())
			updatedApp.Spec.Capabilities = []broker.AppCapabilityType{
				{
					ProducerOf: []broker.AddressRef{{Address: "orders"}},
					ConsumerOf: []broker.AddressRef{
						{
							Address:       "orders",
							Subscriptions: []string{drainOrdersSubName},
						},
					},
				},
			}
			Expect(k8sClient.Update(ctx, updatedApp)).Should(Succeed())

			By("verifying 'events' address is preserved in capabilities.json during drain")
			Eventually(func(g Gomega) {
				secret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())
				capData := secret.Data[configKey]
				g.Expect(capData).ShouldNot(BeEmpty())

				var caps brokerproperties.CapabilitiesJSON
				g.Expect(json.Unmarshal(capData, &caps)).Should(Succeed())
				g.Expect(caps.AddressConfigurations).Should(HaveKey("events"), "events should be preserved during drain")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("verifying 'events' address config preserved during drain with correct per-address roles")
			Eventually(func(g Gomega) {
				secret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())
				capData := secret.Data[configKey]
				g.Expect(capData).ShouldNot(BeEmpty())

				var caps brokerproperties.CapabilitiesJSON
				g.Expect(json.Unmarshal(capData, &caps)).Should(Succeed())

				g.Expect(caps.AddressConfigurations).Should(HaveKey("orders"), "orders address should be present")
				g.Expect(caps.AddressConfigurations).Should(HaveKey("events"), "events address should be preserved during drain")

				hasSendForOrders := false
				if ordersRoles, ok := caps.SecurityRoles["orders"]; ok {
					for _, perms := range ordersRoles {
						if perms.Send {
							hasSendForOrders = true
						}
					}
				}
				g.Expect(hasSendForOrders).Should(BeTrue(), "orders should retain send permission")

				if eventsRoles, ok := caps.SecurityRoles["events"]; ok {
					for roleName, perms := range eventsRoles {
						g.Expect(perms.Send).Should(BeFalse(), "events should not have send permission during drain, role: %s", roleName)
					}
				}
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("consuming messages from 'events' via MQTT to allow drain to complete")
			mqttConsume(ctx, ep, drainClientID, "events", messageCount)

			By("verifying 'events' address config is removed after drain completes")
			Eventually(func(g Gomega) {
				secret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())

				var caps brokerproperties.CapabilitiesJSON
				g.Expect(json.Unmarshal(secret.Data[configKey], &caps)).Should(Succeed())
				g.Expect(caps.AddressConfigurations).Should(HaveKey("orders"), "orders should remain")
				g.Expect(caps.AddressConfigurations).ShouldNot(HaveKey("events"), "events should be removed after drain")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("cleanup")
			cleanupMqttEndpoint(ep)
			Expect(k8sClient.Delete(ctx, updatedApp)).Should(Succeed())
			Eventually(func() bool {
				return errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, &broker.BrokerApp{}))
			}, existingClusterTimeout, existingClusterInterval).Should(BeTrue())
			Expect(k8sClient.Delete(ctx, &service)).Should(Succeed())
			UninstallCert(appName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(serviceName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(common.DefaultPrometheusCertSecretName, defaultNamespace)
		})
	})

	Context("address removal with no messages completes immediately", func() {

		It("should remove address config without entering drain state when queues are empty", func() {

			if os.Getenv("USE_EXISTING_CLUSTER") != "true" {
				return
			}

			ctx := context.Background()
			serviceName := NextSpecResourceName()
			labels := map[string]string{"test": "drain-no-messages"}

			By("creating service")
			service := setupService(ctx, serviceName, labels)

			By("creating app with two addresses: 'orders' and 'events'")
			appName := NextSpecResourceName()
			drainClientID := "drain-client"
			drainOrdersSubName := drainClientID + ".orders"

			app := setupApp(ctx, appName, labels, broker.BrokerAppSpec{
				Capabilities: []broker.AppCapabilityType{
					{
						ProducerOf: []broker.AddressRef{
							{Address: "orders"},
							{Address: "events"},
						},
						ConsumerOf: []broker.AddressRef{
							{
								Address:       "orders",
								Subscriptions: []string{drainOrdersSubName},
							},
							{
								Address:       "events",
								Subscriptions: []string{drainClientID + ".events"},
							},
						},
					},
				},
			})

			By("verifying app is provisioned with both addresses")
			verifyProvisioned(ctx, serviceName, appName)
			verifyCapabilitiesPresent(ctx, serviceName, &app)

			secretName := AppPropertiesSecretName(serviceName)
			configKey := AppIdentityPrefixed(&app, "capabilities.json")
			Eventually(func(g Gomega) {
				secret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())
				g.Expect(string(secret.Data[configKey])).Should(ContainSubstring("orders"))
				g.Expect(string(secret.Data[configKey])).Should(ContainSubstring("events"))
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("removing 'events' address from the app without producing any messages")
			updatedApp := &broker.BrokerApp{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, updatedApp)).Should(Succeed())
			updatedApp.Spec.Capabilities = []broker.AppCapabilityType{
				{
					ProducerOf: []broker.AddressRef{{Address: "orders"}},
					ConsumerOf: []broker.AddressRef{
						{
							Address:       "orders",
							Subscriptions: []string{drainOrdersSubName},
						},
					},
				},
			}
			Expect(k8sClient.Update(ctx, updatedApp)).Should(Succeed())

			By("verifying 'events' address config is removed promptly (no drain needed)")
			Eventually(func(g Gomega) {
				secret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())

				var caps brokerproperties.CapabilitiesJSON
				g.Expect(json.Unmarshal(secret.Data[configKey], &caps)).Should(Succeed())
				g.Expect(caps.AddressConfigurations).Should(HaveKey("orders"), "orders should remain")
				g.Expect(caps.AddressConfigurations).ShouldNot(HaveKey("events"), "events should be removed immediately")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("verifying app remains Ready")
			Eventually(func(g Gomega) {
				drainApp := &broker.BrokerApp{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, drainApp)).Should(Succeed())
				readyCond := meta.FindStatusCondition(drainApp.Status.Conditions, broker.ReadyConditionType)
				g.Expect(readyCond).ShouldNot(BeNil())
				g.Expect(readyCond.Status).Should(Equal(metav1.ConditionTrue), "app should remain Ready when no drain needed")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("cleanup")
			Expect(k8sClient.Delete(ctx, updatedApp)).Should(Succeed())
			Eventually(func() bool {
				return errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, &broker.BrokerApp{}))
			}, existingClusterTimeout, existingClusterInterval).Should(BeTrue())
			Expect(k8sClient.Delete(ctx, &service)).Should(Succeed())
			UninstallCert(appName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(serviceName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(common.DefaultPrometheusCertSecretName, defaultNamespace)
		})
	})

	Context("address removal drains independently when other addresses have messages", func() {

		It("should remove empty address immediately even when another address has pending messages", func() {

			if os.Getenv("USE_EXISTING_CLUSTER") != "true" {
				return
			}

			ctx := context.Background()
			serviceName := NextSpecResourceName()
			labels := map[string]string{"test": "drain-per-addr"}

			By("creating service")
			service := setupService(ctx, serviceName, labels)

			By("creating app with two addresses: 'orders' and 'events'")
			appName := NextSpecResourceName()
			drainClientID := "drain-client"
			drainOrdersSubName := drainClientID + ".orders"
			drainEventsSubName := drainClientID + ".events"

			app := setupApp(ctx, appName, labels, broker.BrokerAppSpec{
				Capabilities: []broker.AppCapabilityType{
					{
						ProducerOf: []broker.AddressRef{
							{Address: "orders"},
							{Address: "events"},
						},
						ConsumerOf: []broker.AddressRef{
							{
								Address:       "orders",
								Subscriptions: []string{drainOrdersSubName},
							},
							{
								Address:       "events",
								Subscriptions: []string{drainEventsSubName},
							},
						},
					},
				},
			})

			By("verifying app is provisioned with both addresses")
			verifyProvisioned(ctx, serviceName, appName)
			verifyCapabilitiesPresent(ctx, serviceName, &app)

			By("setting up MQTT endpoint for messaging")
			ep := setupMqttEndpoint(ctx, serviceName, appName)

			By("establishing durable subscription to 'orders' before producing")
			mqttSubscribe(ctx, ep, drainClientID, "orders")

			By("producing messages to 'orders' only (not 'events')")
			messageCount := 5
			mqttProduce(ctx, ep, "orders", messageCount)

			By("removing 'events' address while 'orders' still has messages")
			updatedApp := &broker.BrokerApp{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, updatedApp)).Should(Succeed())
			updatedApp.Spec.Capabilities = []broker.AppCapabilityType{
				{
					ProducerOf: []broker.AddressRef{{Address: "orders"}},
					ConsumerOf: []broker.AddressRef{
						{
							Address:       "orders",
							Subscriptions: []string{drainOrdersSubName},
						},
					},
				},
			}
			Expect(k8sClient.Update(ctx, updatedApp)).Should(Succeed())

			secretName := AppPropertiesSecretName(serviceName)
			configKey := AppIdentityPrefixed(&app, "capabilities.json")

			By("verifying 'events' address is removed promptly despite 'orders' having messages")
			Eventually(func(g Gomega) {
				secret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())

				var caps brokerproperties.CapabilitiesJSON
				g.Expect(json.Unmarshal(secret.Data[configKey], &caps)).Should(Succeed())
				g.Expect(caps.AddressConfigurations).Should(HaveKey("orders"), "orders should remain")
				g.Expect(caps.AddressConfigurations).ShouldNot(HaveKey("events"), "events should be removed - it has no messages")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("verifying 'orders' still has send permission (not affected by events removal)")
			Eventually(func(g Gomega) {
				secret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())

				var caps brokerproperties.CapabilitiesJSON
				g.Expect(json.Unmarshal(secret.Data[configKey], &caps)).Should(Succeed())

				hasSendForOrders := false
				if ordersRoles, ok := caps.SecurityRoles["orders"]; ok {
					for _, perms := range ordersRoles {
						if perms.Send {
							hasSendForOrders = true
						}
					}
				}
				g.Expect(hasSendForOrders).Should(BeTrue(), "orders should retain full send permission")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("consuming messages from 'orders' to clean up")
			mqttConsume(ctx, ep, drainClientID, "orders", messageCount)

			By("cleanup")
			cleanupMqttEndpoint(ep)
			Expect(k8sClient.Delete(ctx, updatedApp)).Should(Succeed())
			Eventually(func() bool {
				return errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, &broker.BrokerApp{}))
			}, existingClusterTimeout, existingClusterInterval).Should(BeTrue())
			Expect(k8sClient.Delete(ctx, &service)).Should(Succeed())
			UninstallCert(appName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(serviceName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(common.DefaultPrometheusCertSecretName, defaultNamespace)
		})
	})

	Context("re-adding address during drain cancels the drain", func() {

		It("should restore full permissions when a draining address is added back to spec", func() {

			if os.Getenv("USE_EXISTING_CLUSTER") != "true" {
				return
			}

			ctx := context.Background()
			serviceName := NextSpecResourceName()
			labels := map[string]string{"test": "drain-cancel"}

			By("creating service")
			service := setupService(ctx, serviceName, labels)

			By("creating app with two addresses: 'orders' and 'events'")
			appName := NextSpecResourceName()
			drainClientID := "drain-client"
			drainEventsSubName := drainClientID + ".events"
			drainOrdersSubName := drainClientID + ".orders"

			app := setupApp(ctx, appName, labels, broker.BrokerAppSpec{
				Capabilities: []broker.AppCapabilityType{
					{
						ProducerOf: []broker.AddressRef{
							{Address: "orders"},
							{Address: "events"},
						},
						ConsumerOf: []broker.AddressRef{
							{
								Address:       "orders",
								Subscriptions: []string{drainOrdersSubName},
							},
							{
								Address:       "events",
								Subscriptions: []string{drainEventsSubName},
							},
						},
					},
				},
			})

			By("verifying app is provisioned with both addresses")
			verifyProvisioned(ctx, serviceName, appName)
			verifyCapabilitiesPresent(ctx, serviceName, &app)

			By("setting up MQTT endpoint for messaging")
			ep := setupMqttEndpoint(ctx, serviceName, appName)

			By("establishing durable subscription to 'events' before producing")
			mqttSubscribe(ctx, ep, drainClientID, "events")

			By("producing messages to 'events' via MQTT to ensure drain has work to do")
			messageCount := 5
			mqttProduce(ctx, ep, "events", messageCount)

			By("removing 'events' address from the app to start drain")
			updatedApp := &broker.BrokerApp{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, updatedApp)).Should(Succeed())
			updatedApp.Spec.Capabilities = []broker.AppCapabilityType{
				{
					ProducerOf: []broker.AddressRef{{Address: "orders"}},
					ConsumerOf: []broker.AddressRef{
						{
							Address:       "orders",
							Subscriptions: []string{drainOrdersSubName},
						},
					},
				},
			}
			Expect(k8sClient.Update(ctx, updatedApp)).Should(Succeed())

			secretName := AppPropertiesSecretName(serviceName)
			configKey := AppIdentityPrefixed(&app, "capabilities.json")

			By("verifying 'events' is preserved in capabilities.json during drain")
			Eventually(func(g Gomega) {
				secret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())
				capData := secret.Data[configKey]
				g.Expect(capData).ShouldNot(BeEmpty())

				var caps brokerproperties.CapabilitiesJSON
				g.Expect(json.Unmarshal(capData, &caps)).Should(Succeed())
				g.Expect(caps.AddressConfigurations).Should(HaveKey("events"), "events should be preserved during drain")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("re-adding 'events' address back to the app spec to cancel the drain")
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, updatedApp)).Should(Succeed())
				updatedApp.Spec.Capabilities = []broker.AppCapabilityType{
					{
						ProducerOf: []broker.AddressRef{
							{Address: "orders"},
							{Address: "events"},
						},
						ConsumerOf: []broker.AddressRef{
							{
								Address:       "orders",
								Subscriptions: []string{drainOrdersSubName},
							},
							{
								Address:       "events",
								Subscriptions: []string{drainEventsSubName},
							},
						},
					},
				}
				g.Expect(k8sClient.Update(ctx, updatedApp)).Should(Succeed())
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("verifying 'events' has full permissions restored (send and consume)")
			Eventually(func(g Gomega) {
				secret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())
				capData := secret.Data[configKey]
				g.Expect(capData).ShouldNot(BeEmpty())

				var caps brokerproperties.CapabilitiesJSON
				g.Expect(json.Unmarshal(capData, &caps)).Should(Succeed())

				g.Expect(caps.AddressConfigurations).Should(HaveKey("orders"), "orders address should be present")
				g.Expect(caps.AddressConfigurations).Should(HaveKey("events"), "events address should be restored")

				hasSendForEvents := false
				if eventsRoles, ok := caps.SecurityRoles["events"]; ok {
					for _, perms := range eventsRoles {
						if perms.Send {
							hasSendForEvents = true
						}
					}
				}
				g.Expect(hasSendForEvents).Should(BeTrue(), "events should have send permission restored after drain cancel")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("consuming the messages to clean up")
			mqttConsume(ctx, ep, drainClientID, "events", messageCount)

			By("cleanup")
			cleanupMqttEndpoint(ep)
			Expect(k8sClient.Delete(ctx, updatedApp)).Should(Succeed())
			Eventually(func() bool {
				return errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, &broker.BrokerApp{}))
			}, existingClusterTimeout, existingClusterInterval).Should(BeTrue())
			Expect(k8sClient.Delete(ctx, &service)).Should(Succeed())
			UninstallCert(appName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(serviceName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(common.DefaultPrometheusCertSecretName, defaultNamespace)
		})
	})

	Context("service label change triggers drain before unbinding", func() {

		It("should drain when service labels change so app selector no longer matches", func() {

			if os.Getenv("USE_EXISTING_CLUSTER") != "true" {
				return
			}

			ctx := context.Background()
			serviceName := NextSpecResourceName()
			labels := map[string]string{"test": "drain-svc-label"}

			By("creating service")
			setupService(ctx, serviceName, labels)

			By("creating app matching the service")
			appName := NextSpecResourceName()
			drainClientID := "drain-client"
			drainSubName := drainClientID + ".events"
			app := setupApp(ctx, appName, labels, broker.BrokerAppSpec{
				Capabilities: []broker.AppCapabilityType{
					{
						ProducerOf: []broker.AddressRef{{Address: "events"}},
						ConsumerOf: []broker.AddressRef{{
							Address:       "events",
							Subscriptions: []string{drainSubName},
						}},
					},
				},
			})

			By("verifying app is provisioned")
			verifyProvisioned(ctx, serviceName, appName)
			verifyCapabilitiesPresent(ctx, serviceName, &app)

			By("setting up MQTT endpoint for messaging")
			ep := setupMqttEndpoint(ctx, serviceName, appName)

			By("establishing durable subscription before producing")
			mqttSubscribe(ctx, ep, drainClientID, "events")

			By("producing messages to 'events' via MQTT to ensure drain has work to do")
			messageCount := 5
			mqttProduce(ctx, ep, "events", messageCount)

			By("changing service labels so app's selector no longer matches")
			updatedService := &broker.BrokerService{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: defaultNamespace}, updatedService)).Should(Succeed())
			updatedService.Labels = map[string]string{"test": "drain-svc-label-changed"}
			Expect(k8sClient.Update(ctx, updatedService)).Should(Succeed())

			By("verifying app enters draining state")
			Eventually(func(g Gomega) {
				drainApp := &broker.BrokerApp{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, drainApp)).Should(Succeed())

				if verbose {
					fmt.Printf("\n SVC LABEL DRAIN APP STATUS: %v\n", drainApp.Status)
				}

				readyCond := meta.FindStatusCondition(drainApp.Status.Conditions, broker.ReadyConditionType)
				g.Expect(readyCond).ShouldNot(BeNil())
				g.Expect(readyCond.Status).Should(Equal(metav1.ConditionFalse))
				g.Expect(readyCond.Reason).Should(Equal(broker.ReadyConditionUnbindingReason))
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("consuming messages via MQTT to allow drain to complete")
			mqttConsume(ctx, ep, drainClientID, "events", messageCount)

			By("verifying app is unbound after drain completes")
			Eventually(func(g Gomega) {
				drainApp := &broker.BrokerApp{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, drainApp)).Should(Succeed())
				g.Expect(drainApp.Status.Service).Should(BeNil(), "app should be unbound after drain")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("verifying capabilities are removed after drain completes")
			verifyCapabilitiesRemoved(ctx, serviceName, &app)

			By("cleanup")
			cleanupMqttEndpoint(ep)
			Expect(k8sClient.Delete(ctx, &app)).Should(Succeed())
			Eventually(func() bool {
				return errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, &broker.BrokerApp{}))
			}, existingClusterTimeout, existingClusterInterval).Should(BeTrue())
			Expect(k8sClient.Delete(ctx, updatedService)).Should(Succeed())
			UninstallCert(appName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(serviceName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(common.DefaultPrometheusCertSecretName, defaultNamespace)
		})
	})

	Context("service deletion triggers drain before unbinding", func() {

		It("should drain when bound service is deleted while app has messages", func() {

			if os.Getenv("USE_EXISTING_CLUSTER") != "true" {
				return
			}

			ctx := context.Background()
			serviceName := NextSpecResourceName()
			labels := map[string]string{"test": "drain-svc-delete"}

			By("creating service")
			service := setupService(ctx, serviceName, labels)

			By("creating app matching the service")
			appName := NextSpecResourceName()
			drainClientID := "drain-client"
			drainSubName := drainClientID + ".events"
			app := setupApp(ctx, appName, labels, broker.BrokerAppSpec{
				Capabilities: []broker.AppCapabilityType{
					{
						ProducerOf: []broker.AddressRef{{Address: "events"}},
						ConsumerOf: []broker.AddressRef{{
							Address:       "events",
							Subscriptions: []string{drainSubName},
						}},
					},
				},
			})

			By("verifying app is provisioned")
			verifyProvisioned(ctx, serviceName, appName)
			verifyCapabilitiesPresent(ctx, serviceName, &app)

			By("setting up MQTT endpoint for messaging")
			ep := setupMqttEndpoint(ctx, serviceName, appName)

			By("establishing durable subscription before producing")
			mqttSubscribe(ctx, ep, drainClientID, "events")

			By("producing messages to 'events' via MQTT to ensure drain has work to do")
			messageCount := 5
			mqttProduce(ctx, ep, "events", messageCount)

			By("deleting the service while app has unconsumed messages")
			Expect(k8sClient.Delete(ctx, &service)).Should(Succeed())

			By("verifying app enters draining state")
			Eventually(func(g Gomega) {
				drainApp := &broker.BrokerApp{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, drainApp)).Should(Succeed())

				if verbose {
					fmt.Printf("\n SVC DELETE DRAIN APP STATUS: %v\n", drainApp.Status)
				}

				readyCond := meta.FindStatusCondition(drainApp.Status.Conditions, broker.ReadyConditionType)
				g.Expect(readyCond).ShouldNot(BeNil())
				g.Expect(readyCond.Status).Should(Equal(metav1.ConditionFalse))
				g.Expect(readyCond.Reason).Should(Equal(broker.ReadyConditionUnbindingReason))
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("verifying service reports deletion-pending status")
			Eventually(func(g Gomega) {
				svc := &broker.BrokerService{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: defaultNamespace}, svc)).Should(Succeed())

				readyCond := meta.FindStatusCondition(svc.Status.Conditions, broker.ReadyConditionType)
				g.Expect(readyCond).ShouldNot(BeNil())
				g.Expect(readyCond.Status).Should(Equal(metav1.ConditionFalse))
				g.Expect(readyCond.Reason).Should(Equal(broker.ReadyConditionDrainingBeforeDeletion))
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("consuming messages via MQTT to allow drain to complete")
			mqttConsume(ctx, ep, drainClientID, "events", messageCount)

			By("verifying app is unbound after drain completes")
			Eventually(func(g Gomega) {
				drainApp := &broker.BrokerApp{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, drainApp)).Should(Succeed())
				g.Expect(drainApp.Status.Service).Should(BeNil(), "app should be unbound after drain")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("cleanup")
			cleanupMqttEndpoint(ep)
			Expect(k8sClient.Delete(ctx, &app)).Should(Succeed())
			Eventually(func() bool {
				return errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, &broker.BrokerApp{}))
			}, existingClusterTimeout, existingClusterInterval).Should(BeTrue())
			UninstallCert(appName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(serviceName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(common.DefaultPrometheusCertSecretName, defaultNamespace)
		})
	})

	Context("service deletion with multiple bound apps drains all before removal", func() {

		It("should drain both apps when bound service is deleted while apps have messages", func() {

			if os.Getenv("USE_EXISTING_CLUSTER") != "true" {
				return
			}

			ctx := context.Background()
			serviceName := NextSpecResourceName()
			labels := map[string]string{"test": "drain-svc-delete-multi"}

			By("creating service")
			service := setupService(ctx, serviceName, labels)

			By("creating first app with address 'orders'")
			app1Name := NextSpecResourceName()
			app1ClientID := "drain-client-1"
			app1SubName := app1ClientID + ".orders"
			app1 := setupApp(ctx, app1Name, labels, broker.BrokerAppSpec{
				Capabilities: []broker.AppCapabilityType{
					{
						ProducerOf: []broker.AddressRef{{Address: "orders"}},
						ConsumerOf: []broker.AddressRef{{
							Address:       "orders",
							Subscriptions: []string{app1SubName},
						}},
					},
				},
			})

			By("creating second app with address 'events'")
			app2Name := NextSpecResourceName()
			app2ClientID := "drain-client-2"
			app2SubName := app2ClientID + ".events"
			app2 := setupApp(ctx, app2Name, labels, broker.BrokerAppSpec{
				Capabilities: []broker.AppCapabilityType{
					{
						ProducerOf: []broker.AddressRef{{Address: "events"}},
						ConsumerOf: []broker.AddressRef{{
							Address:       "events",
							Subscriptions: []string{app2SubName},
						}},
					},
				},
			})

			By("verifying both apps are provisioned")
			verifyProvisioned(ctx, serviceName, app1Name)
			verifyProvisioned(ctx, serviceName, app2Name)
			verifyCapabilitiesPresent(ctx, serviceName, &app1)
			verifyCapabilitiesPresent(ctx, serviceName, &app2)

			By("setting up MQTT endpoints for messaging")
			ep1 := setupMqttEndpoint(ctx, serviceName, app1Name)
			ep2 := setupMqttEndpoint(ctx, serviceName, app2Name)

			By("establishing durable subscriptions before producing")
			mqttSubscribe(ctx, ep1, app1ClientID, "orders")
			mqttSubscribe(ctx, ep2, app2ClientID, "events")

			By("producing messages to both apps")
			messageCount := 5
			mqttProduce(ctx, ep1, "orders", messageCount)
			mqttProduce(ctx, ep2, "events", messageCount)

			By("deleting the service while both apps have unconsumed messages")
			Expect(k8sClient.Delete(ctx, &service)).Should(Succeed())

			By("verifying both apps enter draining state")
			for _, appName := range []string{app1Name, app2Name} {
				Eventually(func(g Gomega) {
					drainApp := &broker.BrokerApp{}
					g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, drainApp)).Should(Succeed())

					if verbose {
						fmt.Printf("\n SVC DELETE MULTI-APP DRAIN STATUS (%s): %v\n", appName, drainApp.Status)
					}

					readyCond := meta.FindStatusCondition(drainApp.Status.Conditions, broker.ReadyConditionType)
					g.Expect(readyCond).ShouldNot(BeNil())
					g.Expect(readyCond.Status).Should(Equal(metav1.ConditionFalse))
					g.Expect(readyCond.Reason).Should(Equal(broker.ReadyConditionUnbindingReason))
				}, existingClusterTimeout, existingClusterInterval).Should(Succeed())
			}

			By("consuming messages from first app to complete its drain")
			mqttConsume(ctx, ep1, app1ClientID, "orders", messageCount)

			By("verifying first app is unbound after drain completes")
			Eventually(func(g Gomega) {
				drainApp := &broker.BrokerApp{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: app1Name, Namespace: defaultNamespace}, drainApp)).Should(Succeed())
				g.Expect(drainApp.Status.Service).Should(BeNil(), "first app should be unbound after drain")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("verifying service still exists while second app is draining and reports deletion-pending status")
			Eventually(func(g Gomega) {
				svc := &broker.BrokerService{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: defaultNamespace}, svc)).Should(Succeed())
				g.Expect(svc.DeletionTimestamp).ShouldNot(BeNil(), "service should be marked for deletion")
				g.Expect(svc.Finalizers).Should(ContainElement(BrokerServiceDrainFinalizer),
					"service should retain drain finalizer while second app is still draining")

				readyCond := meta.FindStatusCondition(svc.Status.Conditions, broker.ReadyConditionType)
				g.Expect(readyCond).ShouldNot(BeNil())
				g.Expect(readyCond.Status).Should(Equal(metav1.ConditionFalse))
				g.Expect(readyCond.Reason).Should(Equal(broker.ReadyConditionDrainingBeforeDeletion))
				g.Expect(readyCond.Message).Should(ContainSubstring("Deletion pending"))
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("consuming messages from second app to complete its drain")
			mqttConsume(ctx, ep2, app2ClientID, "events", messageCount)

			By("verifying second app is unbound after drain completes")
			Eventually(func(g Gomega) {
				drainApp := &broker.BrokerApp{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: app2Name, Namespace: defaultNamespace}, drainApp)).Should(Succeed())
				g.Expect(drainApp.Status.Service).Should(BeNil(), "second app should be unbound after drain")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("verifying service is deleted after all apps are drained")
			Eventually(func() bool {
				return errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: defaultNamespace}, &broker.BrokerService{}))
			}, existingClusterTimeout, existingClusterInterval).Should(BeTrue())

			By("cleanup")
			cleanupMqttEndpoint(ep1)
			cleanupMqttEndpoint(ep2)
			Expect(k8sClient.Delete(ctx, &app1)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, &app2)).Should(Succeed())
			Eventually(func(g Gomega) {
				g.Expect(errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Name: app1Name, Namespace: defaultNamespace}, &broker.BrokerApp{}))).Should(BeTrue())
				g.Expect(errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Name: app2Name, Namespace: defaultNamespace}, &broker.BrokerApp{}))).Should(BeTrue())
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())
			UninstallCert(app1Name+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(app2Name+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(serviceName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(common.DefaultPrometheusCertSecretName, defaultNamespace)
		})
	})

	Context("removing drain finalizer while messages pending drops app and messages", func() {

		It("should allow immediate deletion when user patches away the drain finalizer", func() {

			if os.Getenv("USE_EXISTING_CLUSTER") != "true" {
				return
			}

			ctx := context.Background()
			serviceName := NextSpecResourceName()
			labels := map[string]string{"test": "drain-finalizer-remove"}

			By("creating service")
			service := setupService(ctx, serviceName, labels)

			By("creating app with address 'orders'")
			appName := NextSpecResourceName()
			drainClientID := "drain-client"
			drainSubName := drainClientID + ".orders"
			app := setupApp(ctx, appName, labels, broker.BrokerAppSpec{
				Capabilities: []broker.AppCapabilityType{
					{
						ProducerOf: []broker.AddressRef{{Address: "orders"}},
						ConsumerOf: []broker.AddressRef{{
							Address:       "orders",
							Subscriptions: []string{drainSubName},
						}},
					},
				},
			})

			By("verifying app is provisioned")
			verifyProvisioned(ctx, serviceName, appName)

			By("setting up MQTT endpoint for messaging")
			ep := setupMqttEndpoint(ctx, serviceName, appName)

			By("establishing durable subscription before producing")
			mqttSubscribe(ctx, ep, drainClientID, "orders")

			By("producing messages to 'orders' via MQTT to ensure drain has work to do")
			messageCount := 5
			mqttProduce(ctx, ep, "orders", messageCount)

			By("deleting the app to trigger drain")
			Expect(k8sClient.Delete(ctx, &app)).Should(Succeed())

			By("verifying app is retained by drain finalizer with draining status")
			Eventually(func(g Gomega) {
				drainApp := &broker.BrokerApp{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, drainApp)).Should(Succeed())

				if verbose {
					fmt.Printf("\nDRAINING APP STATUS before finalizer removal: %v\n", drainApp.Status)
				}
				g.Expect(drainApp.DeletionTimestamp).ShouldNot(BeNil())
				g.Expect(drainApp.Finalizers).Should(ContainElement(BrokerAppDrainFinalizer))

				readyCond := meta.FindStatusCondition(drainApp.Status.Conditions, broker.ReadyConditionType)
				g.Expect(readyCond).ShouldNot(BeNil())
				g.Expect(readyCond.Status).Should(Equal(metav1.ConditionFalse))
				g.Expect(readyCond.Reason).Should(Equal(broker.ReadyConditionUnbindingReason))
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("verifying service reports draining status with message counts")
			Eventually(func(g Gomega) {
				svc := &broker.BrokerService{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: defaultNamespace}, svc)).Should(Succeed())
				if verbose {
					fmt.Printf("\nSERVICE STATUS before finalizer removal: %v\n", svc.Status)
				}
				g.Expect(svc.Status.Draining).ShouldNot(BeEmpty(), "service should report draining entries")
				g.Expect(svc.Status.Draining[0].App).Should(Equal(AppIdentity(&app)))
				g.Expect(svc.Status.Draining[0].Messages).ShouldNot(BeEmpty(), "draining entry should include message counts")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("patching the app to remove the drain finalizer (simulating user bypass)")
			Eventually(func(g Gomega) {
				patchApp := &broker.BrokerApp{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, patchApp)).Should(Succeed())

				updatedFinalizers := []string{}
				for _, f := range patchApp.Finalizers {
					if f != BrokerAppDrainFinalizer {
						updatedFinalizers = append(updatedFinalizers, f)
					}
				}
				patchApp.Finalizers = updatedFinalizers
				g.Expect(k8sClient.Update(ctx, patchApp)).Should(Succeed())
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("verifying app is deleted immediately despite pending messages")
			Eventually(func() bool {
				return errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, &broker.BrokerApp{}))
			}, existingClusterTimeout, existingClusterInterval).Should(BeTrue())

			By("verifying capabilities are removed from secret after forced deletion")
			verifyCapabilitiesRemoved(ctx, serviceName, &app)

			By("verifying service draining status is cleared after app deletion")
			Eventually(func(g Gomega) {
				svc := &broker.BrokerService{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: defaultNamespace}, svc)).Should(Succeed())
				g.Expect(svc.Status.Draining).Should(BeEmpty(), "draining status should be cleared after app forced deletion")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("cleanup")
			cleanupMqttEndpoint(ep)
			Expect(k8sClient.Delete(ctx, &service)).Should(Succeed())
			UninstallCert(appName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(serviceName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(common.DefaultPrometheusCertSecretName, defaultNamespace)
		})
	})

	Context("app deletion should drain anycast address before removal", func() {

		It("should preserve address config until anycast queue is drained via AMQP", func() {

			if os.Getenv("USE_EXISTING_CLUSTER") != "true" {
				return
			}

			ctx := context.Background()
			serviceName := NextSpecResourceName()
			labels := map[string]string{"test": "drain-anycast"}

			By("creating service")
			service := setupService(ctx, serviceName, labels)

			By("creating app with anycast address 'jobs'")
			appName := NextSpecResourceName()
			app := setupApp(ctx, appName, labels, broker.BrokerAppSpec{
				Addresses: []broker.AddressType{
					{Address: "jobs"},
				},
				Capabilities: []broker.AppCapabilityType{
					{
						ProducerOf: []broker.AddressRef{{Address: "jobs"}},
						ConsumerOf: []broker.AddressRef{{Address: "jobs"}},
					},
				},
			})

			By("verifying app is provisioned")
			verifyProvisioned(ctx, serviceName, appName)

			By("verifying capabilities config is in the app-props secret with producer role")
			secretName := AppPropertiesSecretName(serviceName)
			configKey := AppIdentityPrefixed(&app, "capabilities.json")
			Eventually(func(g Gomega) {
				secret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())
				capData, found := secret.Data[configKey]
				g.Expect(found).Should(BeTrue(), "capabilities config should be in secret")
				g.Expect(string(capData)).Should(ContainSubstring(`"send":true`))
				g.Expect(string(capData)).Should(ContainSubstring(`"consume":true`))
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("setting up endpoint for AMQP messaging")
			ep := setupMqttEndpoint(ctx, serviceName, appName)

			By("producing messages to 'jobs' via AMQP")
			messageCount := 5
			amqpProduce(ctx, ep, "jobs", messageCount)

			By("deleting the app")
			Expect(k8sClient.Delete(ctx, &app)).Should(Succeed())

			By("verifying app is retained by drain finalizer with draining status")
			Eventually(func(g Gomega) {
				drainApp := &broker.BrokerApp{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, drainApp)).Should(Succeed())

				if verbose {
					fmt.Printf("\nANYCAST DRAIN APP STATUS: %v\n", drainApp.Status)
				}
				g.Expect(drainApp.DeletionTimestamp).ShouldNot(BeNil())
				g.Expect(drainApp.Finalizers).Should(ContainElement(BrokerAppDrainFinalizer))

				readyCond := meta.FindStatusCondition(drainApp.Status.Conditions, broker.ReadyConditionType)
				g.Expect(readyCond).ShouldNot(BeNil())
				g.Expect(readyCond.Status).Should(Equal(metav1.ConditionFalse))
				g.Expect(readyCond.Reason).Should(Equal(broker.ReadyConditionUnbindingReason))
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("verifying producer role is dropped from capabilities during drain")
			Eventually(func(g Gomega) {
				secret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: defaultNamespace}, secret)).Should(Succeed())
				capData, found := secret.Data[configKey]
				g.Expect(found).Should(BeTrue(), "capabilities config should be preserved during drain")
				g.Expect(string(capData)).ShouldNot(ContainSubstring(`"send":true`), "producer role should be dropped during drain")
				g.Expect(string(capData)).Should(ContainSubstring(`"consume":true`), "consumer role should remain during drain")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("verifying service status reports draining anycast address with message counts")
			Eventually(func(g Gomega) {
				svc := &broker.BrokerService{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: defaultNamespace}, svc)).Should(Succeed())

				if verbose {
					fmt.Printf("\n SERVICE DRAIN STATUS: %v\n", svc.Status)
				}
				g.Expect(svc.Status.Draining).ShouldNot(BeEmpty(), "service status should report draining entries")
				g.Expect(svc.Status.Draining[0].App).Should(Equal(AppIdentity(&app)))
				g.Expect(svc.Status.Draining[0].Messages).ShouldNot(BeEmpty(), "draining entry should include message counts")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("consuming messages from 'jobs' via AMQP to allow drain to complete")
			amqpConsume(ctx, ep, "jobs", messageCount)

			By("verifying app is eventually deleted after drain completes")
			Eventually(func() bool {
				return errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Name: appName, Namespace: defaultNamespace}, &broker.BrokerApp{}))
			}, existingClusterTimeout, existingClusterInterval).Should(BeTrue())

			By("verifying capabilities are removed from secret after drain completion")
			verifyCapabilitiesRemoved(ctx, serviceName, &app)

			By("verifying service draining status is cleared after drain completes")
			Eventually(func(g Gomega) {
				svc := &broker.BrokerService{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: defaultNamespace}, svc)).Should(Succeed())
				g.Expect(svc.Status.Draining).Should(BeEmpty(), "draining status should be cleared after drain completes")
			}, existingClusterTimeout, existingClusterInterval).Should(Succeed())

			By("cleanup")
			cleanupMqttEndpoint(ep)
			Expect(k8sClient.Delete(ctx, &service)).Should(Succeed())
			UninstallCert(appName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(serviceName+"-"+common.DefaultOperandCertSecretName, defaultNamespace)
			UninstallCert(common.DefaultPrometheusCertSecretName, defaultNamespace)
		})
	})
})
