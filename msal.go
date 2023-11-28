package main

// #cgo CFLAGS: -I/opt/halon/include
// #cgo LDFLAGS: -Wl,--unresolved-symbols=ignore-all
// #include <HalonMTA.h>
// #include <stdlib.h>
import "C"
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"unsafe"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

type Config struct {
	Tenants []ConfigTenant `json:"tenants"`
}

type ConfigTenant struct {
	Id           string   `json:"id"`
	Type         string   `json:"type"`
	ClientSecret string   `json:"client_secret"`
	CacheFile    string   `json:"cache_file"`
	ClientId     string   `json:"client_id"`
	Authority    string   `json:"authority"`
	Scopes       []string `json:"scopes"`
}

type PublicTenant struct {
	id     string
	client public.Client
	scopes []string
}

type ConfidentialClient struct {
	id     string
	client confidential.Client
	scopes []string
	secret string
}

var (
	public_tenants       []PublicTenant
	confidential_clients []ConfidentialClient
	lock                 = sync.Mutex{}
)

func main() {}

//export Halon_version
func Halon_version() C.int {
	return C.HALONMTA_PLUGIN_VERSION
}

//export Halon_init
func Halon_init(hic *C.HalonInitContext) C.bool {
	var config *C.HalonConfig
	if !C.HalonMTA_init_getinfo(hic, C.HALONMTA_INIT_CONFIG, nil, 0, unsafe.Pointer(&config), nil) {
		log.Println("Could not get init config")
		return false
	}

	cfg, err := GetConfigAsJSON(config)
	if err != nil {
		log.Println(err.Error())
		return false
	}

	var parsedConfig Config
	json.Unmarshal([]byte(cfg), &parsedConfig)

	for _, tenant := range parsedConfig.Tenants {
		if tenant.Id == "" {
			log.Println("Missing required \"id\" setting for tenant")
			return false
		}
		if tenant.Type == "" {
			log.Println("Missing required \"type\" setting for tenant")
			return false
		}
		if tenant.CacheFile == "" {
			log.Println("Missing required \"cache_file\" setting for tenant")
			return false
		}
		if tenant.ClientId == "" {
			log.Println("Missing required \"client_id\" setting for tenant")
			return false
		}
		if tenant.Type == "confidential" && tenant.ClientSecret == "" {
			log.Println("Missing required \"client_secret\" setting for tenant")
			return false
		}
		if tenant.Authority == "" {
			log.Println("Missing required \"authority\" setting for tenant")
			return false
		}
		if len(tenant.Scopes) == 0 {
			log.Println("Missing or empty \"scopes\" setting for tenant")
			return false
		}

		switch tenant.Type {
		case "public":
			cacheAccessor := &TokenCache{file: tenant.CacheFile}
			client, err := public.New(tenant.ClientId, public.WithCache(cacheAccessor), public.WithAuthority(tenant.Authority))
			if err != nil {
				log.Println(err)
				return false
			}
			public_tenants = append(public_tenants, PublicTenant{id: tenant.Id, client: client, scopes: tenant.Scopes})
		case "confidential":
			cacheAccessor := &TokenCache{file: tenant.CacheFile}
			cred, err := confidential.NewCredFromSecret(tenant.ClientSecret)
			if err != nil {
				log.Println(err)
				return false
			}
			client, err := confidential.New(tenant.Authority, tenant.ClientId, cred, confidential.WithCache(cacheAccessor))
			if err != nil {
				log.Println(err)
				return false
			}
			confidential_clients = append(confidential_clients, ConfidentialClient{id: tenant.Id, client: client, scopes: tenant.Scopes, secret: tenant.ClientSecret})
		default:
			log.Println("Invalid \"type\" setting for tenant")
			return false
		}
	}

	return true
}

func GetTokenByUsernameAndPassword(tenant PublicTenant, username string, password string) (string, error) {
	lock.Lock()
	defer lock.Unlock()

	var userAccount public.Account
	accounts, err := tenant.client.Accounts(context.Background())
	if err != nil {
		return "", err
	}

	for _, account := range accounts {
		if account.PreferredUsername == username {
			userAccount = account
		}
	}

	result, err := tenant.client.AcquireTokenSilent(context.Background(), tenant.scopes, public.WithSilentAccount(userAccount))
	if err != nil {
		result, err = tenant.client.AcquireTokenByUsernamePassword(context.Background(), tenant.scopes, username, password)
		if err != nil {
			return "", err
		}
	}
	return result.AccessToken, nil
}

func GetTokenByCredential(tenant ConfidentialClient) (string, error) {
	lock.Lock()
	defer lock.Unlock()

	result, err := tenant.client.AcquireTokenSilent(context.Background(), tenant.scopes)
	if err != nil {
		result, err = tenant.client.AcquireTokenByCredential(context.Background(), tenant.scopes)
		if err != nil {
			return "", err
		}
	}
	return result.AccessToken, nil
}

//export msal
func msal(hhc *C.HalonHSLContext, args *C.HalonHSLArguments, ret *C.HalonHSLValue) {
	id, err := GetArgumentAsString(args, 0, true)
	if err != nil {
		value := map[string]interface{}{"error": err.Error()}
		SetReturnValueToAny(ret, value)
		return
	}

	for _, tenant := range public_tenants {
		if tenant.id == id {
			options, err := GetArgumentAsJSON(args, 1, true)
			if err != nil {
				value := map[string]interface{}{"error": err.Error()}
				SetReturnValueToAny(ret, value)
				return
			}

			var opts = struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}{}
			json.Unmarshal([]byte(options), &opts)

			token, err := GetTokenByUsernameAndPassword(tenant, opts.Username, opts.Password)
			if err != nil {
				value := map[string]interface{}{"error": err.Error()}
				SetReturnValueToAny(ret, value)
				return
			}

			value := map[string]interface{}{"result": token}
			SetReturnValueToAny(ret, value)
			return
		}
	}

	for _, tenant := range confidential_clients {
		if tenant.id == id {
			token, err := GetTokenByCredential(tenant)
			if err != nil {
				value := map[string]interface{}{"error": err.Error()}
				SetReturnValueToAny(ret, value)
				return
			}

			value := map[string]interface{}{"result": token}
			SetReturnValueToAny(ret, value)
			return
		}
	}

	value := map[string]interface{}{"error": "No tenant matched the \"id\" argument"}
	SetReturnValueToAny(ret, value)
}

//export Halon_hsl_register
func Halon_hsl_register(hhrc *C.HalonHSLRegisterContext) C.bool {
	msal_cs := C.CString("msal")
	C.HalonMTA_hsl_register_function(hhrc, msal_cs, nil)
	C.HalonMTA_hsl_module_register_function(hhrc, msal_cs, nil)
	return true
}

func GetConfigAsJSON(cfg *C.HalonConfig) (string, error) {
	var x *C.char
	y := C.HalonMTA_config_to_json(cfg, &x, nil)
	defer C.free(unsafe.Pointer(x))
	if y {
		return C.GoString(x), nil
	} else {
		if x != nil {
			return "", errors.New(C.GoString(x))
		} else {
			return "", errors.New("failed to get config")
		}
	}
}

func GetArgumentAsString(args *C.HalonHSLArguments, pos uint64, required bool) (string, error) {
	var x = C.HalonMTA_hsl_argument_get(args, C.ulong(pos))
	if x == nil {
		if required {
			return "", fmt.Errorf("missing argument at position %d", pos)
		} else {
			return "", nil
		}
	}
	var y *C.char
	if C.HalonMTA_hsl_value_get(x, C.HALONMTA_HSL_TYPE_STRING, unsafe.Pointer(&y), nil) {
		return C.GoString(y), nil
	} else {
		return "", fmt.Errorf("invalid argument at position %d", pos)
	}
}

func GetArgumentAsJSON(args *C.HalonHSLArguments, pos uint64, required bool) (string, error) {
	var x = C.HalonMTA_hsl_argument_get(args, C.ulong(pos))
	if x == nil {
		if required {
			return "", fmt.Errorf("missing argument at position %d", pos)
		} else {
			return "", nil
		}
	}
	var y *C.char
	z := C.HalonMTA_hsl_value_to_json(x, &y, nil)
	defer C.free(unsafe.Pointer(y))
	if z {
		return C.GoString(y), nil
	} else {
		return "", fmt.Errorf("invalid argument at position %d", pos)
	}
}

func SetReturnValueToAny(ret *C.HalonHSLValue, val interface{}) error {
	x, err := json.Marshal(val)
	if err != nil {
		return err
	}
	y := C.CString(string(x))
	defer C.free(unsafe.Pointer(y))
	var z *C.char
	if !(C.HalonMTA_hsl_value_from_json(ret, y, &z, nil)) {
		if z != nil {
			err = errors.New(C.GoString(z))
			C.free(unsafe.Pointer(z))
		} else {
			err = errors.New("failed to parse return value")
		}
		return err
	}
	return nil
}
