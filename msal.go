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

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

type tenant struct {
	id     string
	client public.Client
	scopes []string
}

var (
	tenants []tenant
	lock    = sync.Mutex{}
)

func main() {}

//export Halon_version
func Halon_version() C.int {
	return C.HALONMTA_PLUGIN_VERSION
}

//export Halon_init
func Halon_init(hic *C.HalonInitContext) C.bool {
	var cfg *C.HalonConfig
	if !C.HalonMTA_init_getinfo(hic, C.HALONMTA_INIT_CONFIG, nil, 0, unsafe.Pointer(&cfg), nil) {
		log.Println("Could not get init config")
		return false
	}

	t := C.HalonMTA_config_object_get(cfg, C.CString("tenants"))
	if t == nil {
		log.Println("Missing required \"tenants\" setting")
		return false
	}

	i := 0
	for {
		y := C.HalonMTA_config_array_get(t, C.ulong(i))
		if y == nil {
			break
		}

		id := C.HalonMTA_config_string_get(C.HalonMTA_config_object_get(y, C.CString("id")), nil)
		if id == nil {
			log.Println("Missing required \"id\" setting")
			return false
		}

		cache_file := C.HalonMTA_config_string_get(C.HalonMTA_config_object_get(y, C.CString("cache_file")), nil)
		if cache_file == nil {
			log.Println("Missing required \"cache_file\" setting")
			return false
		}

		client_id := C.HalonMTA_config_string_get(C.HalonMTA_config_object_get(y, C.CString("client_id")), nil)
		if client_id == nil {
			log.Println("Missing required \"client_id\" setting")
			return false
		}

		authority := C.HalonMTA_config_string_get(C.HalonMTA_config_object_get(y, C.CString("authority")), nil)
		if authority == nil {
			log.Println("Missing required \"authority\" setting")
			return false
		}

		s := C.HalonMTA_config_object_get(y, C.CString("scopes"))
		if s == nil {
			log.Println("Missing required \"scopes\" setting")
			return false
		}

		var scopes []string
		z := 0
		for {
			scope := C.HalonMTA_config_string_get(C.HalonMTA_config_array_get(s, C.ulong(z)), nil)
			if scope == nil {
				break
			}
			scopes = append(scopes, C.GoString(scope))
			z++
		}
		if len(scopes) == 0 {
			log.Println("Invalid \"scopes\" setting")
			return false
		}

		cacheAccessor := &TokenCache{file: C.GoString(cache_file)}
		c, err := public.New(C.GoString(client_id), public.WithCache(cacheAccessor), public.WithAuthority(C.GoString(authority)))
		if err != nil {
			log.Println(err)
			return false
		}
		tenants = append(tenants, tenant{id: C.GoString(id), client: c, scopes: scopes})

		i++
	}

	return true
}

func set_ret_value(ret *C.HalonHSLValue, key string, value string) {
	var ret_key *C.HalonHSLValue
	var ret_value *C.HalonHSLValue
	C.HalonMTA_hsl_value_array_add(ret, &ret_key, &ret_value)
	C.HalonMTA_hsl_value_set(ret_key, C.HALONMTA_HSL_TYPE_STRING, unsafe.Pointer(C.CString(key)), 0)
	C.HalonMTA_hsl_value_set(ret_value, C.HALONMTA_HSL_TYPE_STRING, unsafe.Pointer(C.CString(value)), 0)
}

func get_token_by_username_and_password(tenant tenant, username string, password string) (string, error) {
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

//export msal
func msal(hhc *C.HalonHSLContext, args *C.HalonHSLArguments, ret *C.HalonHSLValue) {
	var id *C.char
	var username *C.char
	var password *C.char

	var args_0 = C.HalonMTA_hsl_argument_get(args, 0)
	if args_0 != nil {
		if C.HalonMTA_hsl_value_type(args_0) == C.HALONMTA_HSL_TYPE_ARRAY {
			var args_0_id_str = C.CString("id")
			defer C.free(unsafe.Pointer(args_0_id_str))
			var args_0_id *C.HalonHSLValue = C.HalonMTA_hsl_value_array_find(args_0, args_0_id_str)
			if args_0_id == nil {
				set_ret_value(ret, "error", "Could not find \"id\" option")
				return
			}
			if !C.HalonMTA_hsl_value_get(args_0_id, C.HALONMTA_HSL_TYPE_STRING, unsafe.Pointer(&id), nil) {
				set_ret_value(ret, "error", "Invalid type of \"id\" option")
				return
			}

			var args_0_username_str = C.CString("username")
			defer C.free(unsafe.Pointer(args_0_username_str))
			var args_0_username *C.HalonHSLValue = C.HalonMTA_hsl_value_array_find(args_0, args_0_username_str)
			if args_0_username == nil {
				set_ret_value(ret, "error", "Could not find \"username\" option")
				return
			}
			if !C.HalonMTA_hsl_value_get(args_0_username, C.HALONMTA_HSL_TYPE_STRING, unsafe.Pointer(&username), nil) {
				set_ret_value(ret, "error", "Invalid type of \"username\" option")
				return
			}

			var args_0_password_str = C.CString("password")
			defer C.free(unsafe.Pointer(args_0_password_str))
			var args_0_password *C.HalonHSLValue = C.HalonMTA_hsl_value_array_find(args_0, args_0_password_str)
			if args_0_password == nil {
				set_ret_value(ret, "error", "Could not find \"password\" option")
				return
			}
			if !C.HalonMTA_hsl_value_get(args_0_password, C.HALONMTA_HSL_TYPE_STRING, unsafe.Pointer(&password), nil) {
				set_ret_value(ret, "error", "Invalid type of \"password\" option")
				return
			}
		} else {
			set_ret_value(ret, "error", "Invalid type of \"options\" argument")
			return
		}
	} else {
		set_ret_value(ret, "error", "Missing required \"options\" argument")
		return
	}
	for _, tenant := range tenants {
		if tenant.id == C.GoString(id) {
			token, err := get_token_by_username_and_password(tenant, C.GoString(username), C.GoString(password))
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
	C.HalonMTA_hsl_register_function(hhrc, C.CString("msal"), nil)
	return true
}
