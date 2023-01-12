package nhost

import (
	"errors"
	"fmt"
	"github.com/beepshow/nhost-go/common"
	"github.com/beepshow/nhost-go/hasura_auth"
	"github.com/beepshow/nhost-go/hasura_storage"
	"github.com/oriser/regroup"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
)

type NhostFunctionsClient struct {
}

type NhostGraphqlClient struct {
}

type ServiceType int64

const (
	Auth ServiceType = iota
	Storage
	Functions
	Graphql
)

var (
	serviceNames = []string{"auth", "storage", "functions", "graphql"}
)

type NhostClient struct {
	Auth         *hasura_auth.AuthClient
	Storage      *hasura_storage.HasuraStorageClient
	Functions    *NhostFunctionsClient
	Graphql      *NhostGraphqlClient
	Urls         map[ServiceType]string
	_adminSecret string
}

func NewWithClientStorage(subdomain string, region string, clientStorage hasura_auth.ClientStorage) (*NhostClient, error) {
	urls := make(map[ServiceType]string)
	url, err := urlFromSubdomain(subdomain, region, Auth)
	if err != nil {
		return nil, err
	}
	urls[Auth] = url
	auth, err := hasura_auth.New(
		url,
		"",
		true,
		true,
		true,
		clientStorage,
		0,
		true,
	)
	if err != nil {
		return nil, err
	}

	url, err = urlFromSubdomain(subdomain, region, Storage)
	if err != nil {
		return nil, err
	}
	urls[Storage] = url
	storage, err := hasura_storage.NewWithSubdomain(
		url,
		"",
		subdomain,
	)
	if err != nil {
		return nil, err
	}

	url, err = urlFromSubdomain(subdomain, region, Functions)
	if err != nil {
		return nil, err
	}
	urls[Functions] = url

	url, err = urlFromSubdomain(subdomain, region, Graphql)
	if err != nil {
		return nil, err
	}
	urls[Graphql] = url

	client := &NhostClient{
		Auth:         auth,
		Storage:      storage,
		Functions:    &NhostFunctionsClient{},
		Graphql:      &NhostGraphqlClient{},
		Urls:         urls,
		_adminSecret: "",
	}

	client.Auth.OnAuthStateChanged(func(event hasura_auth.AuthChangeEvent, session *hasura_auth.Session) {
		if event == hasura_auth.SIGNED_OUT {
			storage.AccessToken = ""
		}
	})

	client.Auth.OnTokenChanged(func(session *hasura_auth.Session) {
		if session == nil {
			storage.AccessToken = ""
		} else {
			storage.AccessToken = session.AccessToken
		}
	})

	return client, nil
}

func New(subdomain string, region string) (*NhostClient, error) {
	clientStorage, err := hasura_auth.DefaultClientStorage()
	if err != nil {
		return nil, err
	}
	return NewWithClientStorage(subdomain, region, clientStorage)
}

func urlFromSubdomain(subdomain string, region string, service ServiceType) (string, error) {
	switch service {
	case Auth:
		log.Debugln("creating auth")
	case Storage:
		log.Debugln("creating storage")
	case Functions:
		log.Debugln("creating functions")
	case Graphql:
		log.Debugln("creating graphql")
	default:
		return "", errors.New("unknown ServiceType")
	}

	//// check if subdomain is [http[s]://]localhost[:port]
	// Using regroup instead of regexp because regroup provides easier access to named groups
	var localhostRegex = regroup.MustCompile(common.LOCALHOST_REGEX)
	res := &common.UrlMatchResult{}
	err := localhostRegex.MatchToTarget(subdomain, res)
	// If match
	if err == nil {
		//fmt.Printf("by struct: %+v\n", res)

		urlFromEnv := getValueFromEnv(service)
		if urlFromEnv != "" {
			return urlFromEnv, nil
		}

		if res.Protocol == "" {
			res.Protocol = "http"
		}
		if res.Port == 0 {
			res.Port = 1337
		}

		//return `${protocol}://${host}:${port}/v1/${service}`
		return fmt.Sprintf("%s://%s:%d/v1/%s", res.Protocol, res.Host, res.Port, serviceNames[service]), nil
	}

	//panic or return error?
	if region == "" {
		panic(`region must be set when using a "subdomain" other than "localhost".`)
	}

	//return `https://${subdomain}.${service}.${region}.nhost.run/v1`
	return fmt.Sprintf("https://%s.%s.%s.nhost.run/v1", subdomain, serviceNames[service], region), nil
}

/**
*
* @param service Auth | Storage | Graphql | Functions
* @returns the service's url if the corresponding env var is set
* NHOST_${service}_URL
 */
func getValueFromEnv(service ServiceType) string {
	return os.Getenv(fmt.Sprintf("NHOST_%s_URL", strings.ToUpper(serviceNames[service])))
}
