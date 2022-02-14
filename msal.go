package main

// #cgo CFLAGS: -I/opt/halon/include
// #cgo LDFLAGS: -Wl,--unresolved-symbols=ignore-all
// #include <HalonMTA.h>
// #include <stdlib.h>
import "C"
import (
	"context"
	"log"
	"sync"
	"unsafe"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

type public_tenant struct {
	id     string
	client public.Client
	scopes []string
}

type confidential_client struct {
	id     string
	client confidential.Client
	scopes []string
	secret string
}

var (
	public_tenants       []public_tenant
	confidential_clients []confidential_client
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
				public_tenants = append(public_tenants, public_tenant{id: id, client: client, scopes: scopes})
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
				confidential_clients = append(confidential_clients, confidential_client{id: id, client: client, scopes: scopes, secret: client_secret})
			default:
				log.Println("Empty or invalid \"type\" setting for tenant")
				return false
			}

			i++
		}
	}

	return true
}

func set_ret_value(ret *C.HalonHSLValue, key string, value string) {
	var ret_key *C.HalonHSLValue
	var ret_value *C.HalonHSLValue
	C.HalonMTA_hsl_value_array_add(ret, &ret_key, &ret_value)
	key_cs := C.CString(key)
	key_cs_up := unsafe.Pointer(key_cs)
	defer C.free(key_cs_up)
	value_cs := C.CString(value)
	value_cs_up := unsafe.Pointer(value_cs)
	defer C.free(value_cs_up)

	C.HalonMTA_hsl_value_set(ret_key, C.HALONMTA_HSL_TYPE_STRING, key_cs_up, 0)
	C.HalonMTA_hsl_value_set(ret_value, C.HALONMTA_HSL_TYPE_STRING, value_cs_up, 0)
}

func get_token_by_username_and_password(tenant public_tenant, username string, password string) (string, error) {
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

func get_token_by_credential(tenant confidential_client) (string, error) {
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
	var id string
	var id_cs *C.char
	var username string
	var username_cs *C.char
	var password string
	var password_cs *C.char

	var args_0 = C.HalonMTA_hsl_argument_get(args, 0)
	if args_0 != nil {
		if !C.HalonMTA_hsl_value_get(args_0, C.HALONMTA_HSL_TYPE_STRING, unsafe.Pointer(&id_cs), nil) {
			set_ret_value(ret, "error", "Invalid type of \"id\" argument")
			return
		}
		id = C.GoString(id_cs)
	} else {
		set_ret_value(ret, "error", "Missing required \"id\" argument")
		return
	}

	for _, tenant := range public_tenants {
		if tenant.id == id {
			var args_1 = C.HalonMTA_hsl_argument_get(args, 1)
			if args_1 != nil {
				if C.HalonMTA_hsl_value_type(args_1) == C.HALONMTA_HSL_TYPE_ARRAY {
					var args_1_username_cs = C.CString("username")
					defer C.free(unsafe.Pointer(args_1_username_cs))
					var args_1_username *C.HalonHSLValue = C.HalonMTA_hsl_value_array_find(args_1, args_1_username_cs)
					if args_1_username == nil {
						set_ret_value(ret, "error", "Could not find \"username\" option")
						return
					}
					if !C.HalonMTA_hsl_value_get(args_1_username, C.HALONMTA_HSL_TYPE_STRING, unsafe.Pointer(&username_cs), nil) {
						set_ret_value(ret, "error", "Invalid type of \"username\" option")
						return
					}
					username = C.GoString(username_cs)

					var args_1_password_cs = C.CString("password")
					defer C.free(unsafe.Pointer(args_1_password_cs))
					var args_1_password *C.HalonHSLValue = C.HalonMTA_hsl_value_array_find(args_1, args_1_password_cs)
					if args_1_password == nil {
						set_ret_value(ret, "error", "Could not find \"password\" option")
						return
					}
					if !C.HalonMTA_hsl_value_get(args_1_password, C.HALONMTA_HSL_TYPE_STRING, unsafe.Pointer(&password_cs), nil) {
						set_ret_value(ret, "error", "Invalid type of \"password\" option")
						return
					}
					password = C.GoString(password_cs)
				} else {
					set_ret_value(ret, "error", "Invalid type of \"options\" argument")
					return
				}
			} else {
				set_ret_value(ret, "error", "Missing required \"options\" argument")
				return
			}

			token, err := get_token_by_username_and_password(tenant, username, password)
			if err != nil {
				set_ret_value(ret, "error", err.Error())
				return
			}

			set_ret_value(ret, "result", token)
			return
		}
	}

	for _, tenant := range confidential_clients {
		if tenant.id == id {
			token, err := get_token_by_credential(tenant)
			if err != nil {
				set_ret_value(ret, "error", err.Error())
				return
			}

			set_ret_value(ret, "result", token)
			return
		}
	}

	set_ret_value(ret, "error", "No tenant matched the \"id\" argument")
}

//export Halon_hsl_register
func Halon_hsl_register(hhrc *C.HalonHSLRegisterContext) C.bool {
	msal_cs := C.CString("msal")
	C.HalonMTA_hsl_register_function(hhrc, msal_cs, nil)
	return true
}
