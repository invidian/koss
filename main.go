package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	gosysctl "github.com/lorenzosaino/go-sysctl"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

const (
	certValidityDuration = 1 * time.Hour
	apiPrefix            = "/apis/koss.invidian.github.io/v1alpha1"
	sysctlAPI            = "sysctl"
	ip                   = "127.0.0.1"
	port                 = 8443
)

type sysctl struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Value             string `json:"value,omitempty"`
}

func main() {
	certificate, ca, err := selfSignedCerts()
	if err != nil {
		panic(err)
	}

	path, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	kubeconfigContent := fmt.Sprintf(`apiVersion: v1
clusters:
- cluster:
    server: https://%s:%d
    certificate-authority-data: %s
  name: test
contexts:
- context:
    cluster: test
    namespace: kube-system
    user: test
  name: test
current-context: test
kind: Config
preferences: {}
users:
- name: test
  user:
    token: test
`, ip, port, base64.StdEncoding.EncodeToString([]byte(ca)))

	kubeconfigPath := filepath.Join(path, "kubeconfig")

	if err := ioutil.WriteFile(kubeconfigPath, []byte(kubeconfigContent), 0o600); err != nil {
		panic(err)
	}

	fmt.Printf("To test in standalone mode, without Kubernetes API server, use kubeconfig file written to %q\n",
		kubeconfigPath)

	mux := http.NewServeMux()

	mux.HandleFunc("/", dispatch)

	server := http.Server{
		Addr: fmt.Sprintf(":%d", port),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{
				*certificate,
			},
		},
		Handler: mux,
	}

	if err := server.ListenAndServeTLS("", ""); err != nil {
		panic(err)
	}
}

func dispatch(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/apis" {
		apis(w)

		return
	}

	if req.URL.Path == "/openapi/v2" {
		openapi(w)

		return
	}

	if !strings.HasPrefix(req.URL.Path, apiPrefix) {
		dump(w, req)

		return
	}

	if req.Method == "GET" && req.URL.Path == apiPrefix {
		api(w, req)

		return
	}

	api := fmt.Sprintf("%s/%s", apiPrefix, sysctlAPI)

	if req.URL.Path == api {
		if req.Method == "GET" {
			list(w, req)

			return
		}

		if req.Method == "POST" {
			bodyBytes, err := ioutil.ReadAll(req.Body)
			if err != nil {
				panic(err)
			}

			sysctl := &sysctl{}
			if err := yaml.Unmarshal(bodyBytes, sysctl); err != nil {
				panic(err)
			}

			set(w, sysctl.Name, sysctl.Value)

			return
		}
	}

	if strings.HasPrefix(req.URL.Path, fmt.Sprintf("%s/", api)) {
		v, ok := req.Header["Accept"]
		if !ok {
			panic("bad request")
		}

		key := strings.TrimPrefix(req.URL.Path, fmt.Sprintf("%s/", api))

		if req.Method == "GET" {
			for _, v := range strings.Split(v[0], ";") {
				if v == "as=Table" {
					getTable(w, key)

					return
				}
			}

			get(w, strings.TrimPrefix(req.URL.Path, fmt.Sprintf("%s/", api)))

			return
		}

		if req.Method != "GET" {
			log.Printf("Got request for key %q", key)
		}

		if req.Method == "PATCH" {
			bodyBytes, err := ioutil.ReadAll(req.Body)
			if err != nil {
				panic(err)
			}

			sysctl := &sysctl{}
			if err := yaml.Unmarshal(bodyBytes, sysctl); err != nil {
				panic(err)
			}

			set(w, key, sysctl.Value)

			return
		}
	}

	dump(w, req)
}

func openapi(w http.ResponseWriter) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	data := fmt.Sprintf(`{
  "swagger": "2.0",
  "info": {
    "title": "Kubernetes",
    "version": "v1.21.1"
  },
  "paths": {
    "%s": {
      "get": {
        "description": "get available sysctl knobs",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "schemes": [
          "https"
        ],
        "operationId": "getSysctlV1alpha1APIResources",
        "responses": {
          "200": {
            "description": "OK"
          }
        }
      }
    },
    "%s/{name}": {
      "get": {
        "description": "get single sysctl knob",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "schemes": [
          "https"
        ],
        "operationId": "readSysctlV1alpha1",
        "responses": {
          "200": {
            "description": "OK"
          }
        }
      },
      "parameters": [
        {
          "uniqueItems": true,
          "type": "string",
          "description": "name of the sysctl knob",
          "name": "name",
          "in": "path",
          "required": true
        }
      ]
    }
  },
  "definitions: {
    "io.github.invidian.koss.v1alpha1.Sysctl": {
      "description": "Sysctl knob.",
      "type": "object",
      "required": [
        "value"
      ],
      "properties": {
        "apiVersion": {
          "type": "string"
        },
        "kind": {
          "type": "string"
        },
        "value": {
          "type": "string"
        }
      },
      "x-kubernetes-group-version-kind": [
        {
          "group": "koss.invidian.github.io",
          "kind": "Sysctl",
          "version": "v1alpha1"
        }
      ]
    }
  }
}
`, apiPrefix, apiPrefix)

	w.Write([]byte(data))
}

func apis(w http.ResponseWriter) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	data := `{
  "kind": "APIGroupList",
  "apiVersion": "v1",
  "groups": [
		{
      "name": "koss.invidian.github.io",
      "versions": [
        {
          "groupVersion": "koss.invidian.github.io/v1alpha1",
          "version": "v1alpha1"
        }
      ],
      "preferredVersion": {
        "groupVersion": "koss.invidian.github.io/v1alpha1",
        "version": "v1alpha1"
      }
    }
  ]
}`

	w.Write([]byte(data))
}

func set(w http.ResponseWriter, name string, value string) {
	if err := gosysctl.Set(name, value); err != nil {
		panic(err)
	}

	get(w, name)
}

func get(w http.ResponseWriter, name string) {
	log.Printf("GET %q", name)
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	val, err := gosysctl.Get(name)
	if err != nil {
		panic(err)
	}

	data := fmt.Sprintf(`{
  "kind": "Sysctl",
  "apiVersion": "koss.invidian.github.io/v1alpha1",
  "metadata": {
    "name": "%s"
  },
  "value": "%s"
}`, name, val)

	w.Write([]byte(data))
}

func getTable(w http.ResponseWriter, name string) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	val, err := gosysctl.Get(name)
	if err != nil {
		panic(err)
	}

	t := &metav1.Table{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Table",
			APIVersion: "meta.k8s.io/v1",
		},
		ColumnDefinitions: []metav1.TableColumnDefinition{
			{
				Name: "Name",
				Type: "string",
			},
			{
				Name: "Value",
				Type: "string",
			},
		},
		Rows: []metav1.TableRow{
			{
				Cells: []interface{}{
					name,
					val,
				},
			},
		},
	}

	bytes, err := json.Marshal(t)
	if err != nil {
		panic(err)
	}

	w.Write(bytes)
}

// List.
func list(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	vals, err := gosysctl.GetAll()
	if err != nil {
		panic(err)
	}

	keys := []string{}

	for k := range vals {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	rows := []metav1.TableRow{}

	for _, k := range keys {
		rows = append(rows, metav1.TableRow{
			Cells: []interface{}{
				k,
				vals[k],
			},
		})
	}

	t := &metav1.Table{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Table",
			APIVersion: "meta.k8s.io/v1",
		},
		ColumnDefinitions: []metav1.TableColumnDefinition{
			{
				Name: "Name",
				Type: "string",
			},
			{
				Name: "Value",
				Type: "string",
			},
		},
		Rows: rows,
	}

	bytes, err := json.Marshal(t)
	if err != nil {
		panic(err)
	}

	w.Write(bytes)
}

func api(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
  "kind": "APIResourceList",
  "apiVersion": "v1",
  "groupVersion": "koss.invidian.github.io/v1alpha1",
  "resources": [
    {
      "name": "sysctl",
      "singularName": "",
      "namespaced": false,
      "kind": "Sysctl",
      "verbs": [
        "list"
      ]
    }
	]
}`))
}

func dump(w http.ResponseWriter, req *http.Request) {
	log.Printf("Method: %q URL: %q", req.Method, req.URL.Path)
	log.Printf("PostForm: %s", req.PostForm)
	log.Printf("  Headers:")

	for k, v := range req.Header {
		log.Printf("    %s: %s", k, v)
	}

	bodyBytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		panic(err)
	}
	log.Printf("Body: %s", string(bodyBytes))

	log.Printf("-----------------------------------")
	w.WriteHeader(http.StatusOK)
	w.Header().Add("Content-Type", "application/json")
	w.Write([]byte("{}"))
}

func selfSignedCerts() (*tls.Certificate, []byte, error) {
	// Generate RSA private key.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generating RSA key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(certValidityDuration),
		IPAddresses:  []net.IP{net.ParseIP(ip)},
	}

	// Create X.509 certificate in DER format.
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("creating X.509 certificate: %w", err)
	}

	// Encode X.509 certificate into PEM format.
	var cert bytes.Buffer
	if err := pem.Encode(&cert, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return nil, nil, fmt.Errorf("encoding X.509 certificate as PEM: %w", err)
	}

	// Convert RSA private key into PKCS8 DER format.
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("converting RSA private key to PKCS8: %w", err)
	}

	// Convert private key from PKCS8 DER format to PEM format.
	var key bytes.Buffer
	if err := pem.Encode(&key, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, nil, fmt.Errorf("encoding PKCS8 private key to PEM: %w", err)
	}

	certificate, err := tls.X509KeyPair(cert.Bytes(), key.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf("initializing X.509 keypair: %w", err)
	}

	return &certificate, cert.Bytes(), nil
}
