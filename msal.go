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

	tenants_prop_cs := C.CString("tenants")
	defer C.free(unsafe.Pointer(tenants_prop_cs))
	tenants_chc := C.HalonMTA_config_object_get(config, tenants_prop_cs)
	if tenants_chc != nil {
		i := 0
		for {
			i_cul := C.ulong(i)
			tenant_chc := C.HalonMTA_config_array_get(tenants_chc, i_cul)
			if tenant_chc == nil {
				break
			}

			id_prop_cs := C.CString("id")
			defer C.free(unsafe.Pointer(id_prop_cs))
			id_cs := C.HalonMTA_config_string_get(C.HalonMTA_config_object_get(tenant_chc, id_prop_cs), nil)
			if id_cs == nil {
				log.Println("Missing required \"id\" setting for tenant")
				return false
			}
			id := C.GoString(id_cs)

			type_prop_cs := C.CString("type")
			defer C.free(unsafe.Pointer(type_prop_cs))
			type_cs := C.HalonMTA_config_string_get(C.HalonMTA_config_object_get(tenant_chc, type_prop_cs), nil)
			if type_cs == nil {
				log.Println("Missing required \"type\" setting for tenant")
				return false
			}
			_type := C.GoString(type_cs)

			cache_file_prop_cs := C.CString("cache_file")
			defer C.free(unsafe.Pointer(cache_file_prop_cs))
			cache_file_cs := C.HalonMTA_config_string_get(C.HalonMTA_config_object_get(tenant_chc, cache_file_prop_cs), nil)
			if cache_file_cs == nil {
				log.Println("Missing required \"cache_file\" setting for tenant")
				return false
			}
			cache_file := C.GoString(cache_file_cs)

			client_id_prop_cs := C.CString("client_id")
			defer C.free(unsafe.Pointer(client_id_prop_cs))
			client_id_cs := C.HalonMTA_config_string_get(C.HalonMTA_config_object_get(tenant_chc, client_id_prop_cs), nil)
			if client_id_cs == nil {
				log.Println("Missing required \"client_id\" setting for tenant")
				return false
			}
			client_id := C.GoString(client_id_cs)

			var client_secret string
			if _type == "confidential" {
				client_secret_prop_cs := C.CString("client_secret")
				defer C.free(unsafe.Pointer(client_secret_prop_cs))
				client_secret_cs := C.HalonMTA_config_string_get(C.HalonMTA_config_object_get(tenant_chc, client_secret_prop_cs), nil)
				if client_secret_cs == nil {
					log.Println("Missing required \"client_secret\" setting for tenant")
					return false
				}
				client_secret = C.GoString(client_secret_cs)
			}

			authority_prop_cs := C.CString("authority")
			defer C.free(unsafe.Pointer(authority_prop_cs))
			authority_cs := C.HalonMTA_config_string_get(C.HalonMTA_config_object_get(tenant_chc, authority_prop_cs), nil)
			if authority_cs == nil {
				log.Println("Missing required \"authority\" setting for tenant")
				return false
			}
			authority := C.GoString(authority_cs)

			scopes_prop_cs := C.CString("scopes")
			defer C.free(unsafe.Pointer(scopes_prop_cs))
			scopes_chc := C.HalonMTA_config_object_get(tenant_chc, scopes_prop_cs)
			if scopes_chc == nil {
				log.Println("Missing required \"scopes\" setting for tenant")
				return false
			}

			var scopes []string
			y := 0
			for {
				y_cul := C.ulong(y)
				scope_cs := C.HalonMTA_config_string_get(C.HalonMTA_config_array_get(scopes_chc, y_cul), nil)
				if scope_cs == nil {
					break
				}
				scope := C.GoString(scope_cs)
				scopes = append(scopes, scope)
				y++
			}
			if len(scopes) == 0 {
				log.Println("Empty or invalid \"scopes\" setting for tenant")
				return false
			}

			switch _type {
			case "public":
				cacheAccessor := &TokenCache{file: cache_file}
				client, err := public.New(client_id, public.WithCache(cacheAccessor), public.WithAuthority(authority))
				if err != nil {
					log.Println(err)
					return false
				}
				public_tenants = append(public_tenants, PublicTenant{id: id, client: client, scopes: scopes})
			case "confidential":
				cacheAccessor := &TokenCache{file: cache_file}
				cred, err := confidential.NewCredFromSecret(client_secret)
				if err != nil {
					log.Println(err)
					return false
				}
				client, err := confidential.New(client_id, cred, confidential.WithAccessor(cacheAccessor), confidential.WithAuthority(authority))
				if err != nil {
					log.Println(err)
					return false
				}
				confidential_clients = append(confidential_clients, ConfidentialClient{id: id, client: client, scopes: scopes, secret: client_secret})
			default:
				log.Println("Empty or invalid \"type\" setting for tenant")
				return false
			}

			i++
		}
	}

	return true
}

func GetTokenByUsernameAndPassword(tenant PublicTenant, username string, password string) (string, error) {
	lock.Lock()
	defer lock.Unlock()

	var userAccount public.Account
	accounts := tenant.client.Accounts()
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
