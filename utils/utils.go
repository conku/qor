package utils

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"time"

	"github.com/conku/qor"
	"github.com/gosimple/slug"
	"github.com/jinzhu/now"
	"github.com/microcosm-cc/bluemonday"
	"gorm.io/gorm"

	"strings"
)

// AppRoot app root path
var AppRoot, _ = os.Getwd()

// ContextKey defined type used for context's key
type ContextKey string

// ContextDBName db name used for context
var ContextDBName ContextKey = "ContextDB"

// HTMLSanitizer html sanitizer to avoid XSS
var HTMLSanitizer = bluemonday.UGCPolicy()

func init() {
	HTMLSanitizer.AllowStandardAttributes()
	if path := os.Getenv("WEB_ROOT"); path != "" {
		AppRoot = path
	}
}

// GOPATH return GOPATH from env
func GOPATH() []string {
	paths := strings.Split(os.Getenv("GOPATH"), string(os.PathListSeparator))
	if len(paths) == 0 {
		fmt.Println("GOPATH doesn't exist")
	}
	return paths
}

// GetDBFromRequest get database from request
var GetDBFromRequest = func(req *http.Request) *gorm.DB {
	db := req.Context().Value(ContextDBName)
	if tx, ok := db.(*gorm.DB); ok {
		return tx
	}

	return nil
}

// HumanizeString Humanize separates string based on capitalizd letters
// e.g. "OrderItem" -> "Order Item"
func HumanizeString(str string) string {
	var human []rune
	for i, l := range str {
		if i > 0 && isUppercase(byte(l)) {
			if (!isUppercase(str[i-1]) && str[i-1] != ' ') || (i+1 < len(str) && !isUppercase(str[i+1]) && str[i+1] != ' ' && str[i-1] != ' ') {
				human = append(human, rune(' '))
			}
		}
		human = append(human, l)
	}
	return strings.Title(string(human))
}

func isUppercase(char byte) bool {
	return 'A' <= char && char <= 'Z'
}

var asicsiiRegexp = regexp.MustCompile("^(\\w|\\s|-|!)*$")

// ToParamString replaces spaces and separates words (by uppercase letters) with
// underscores in a string, also downcase it
// e.g. ToParamString -> to_param_string, To ParamString -> to_param_string
func ToParamString(str string) string {
	if asicsiiRegexp.MatchString(str) {
		return gorm.ToDBName(strings.Replace(str, " ", "_", -1))
	}
	return slug.Make(str)
}

// PatchURL updates the query part of the request url.
//
//	PatchURL("google.com","key","value") => "google.com?key=value"
func PatchURL(originalURL string, params ...interface{}) (patchedURL string, err error) {
	url, err := url.Parse(originalURL)
	if err != nil {
		return
	}

	query := url.Query()
	for i := 0; i < len(params)/2; i++ {
		// Check if params is key&value pair
		key := fmt.Sprintf("%v", params[i*2])
		value := fmt.Sprintf("%v", params[i*2+1])

		if value == "" {
			query.Del(key)
		} else {
			query.Set(key, value)
		}
	}

	url.RawQuery = query.Encode()
	patchedURL = url.String()
	return
}

// JoinURL updates the path part of the request url.
//
//	JoinURL("google.com", "admin") => "google.com/admin"
//	JoinURL("google.com?q=keyword", "admin") => "google.com/admin?q=keyword"
func JoinURL(originalURL string, paths ...interface{}) (joinedURL string, err error) {
	u, err := url.Parse(originalURL)
	if err != nil {
		return
	}

	var urlPaths = []string{u.Path}
	for _, p := range paths {
		urlPaths = append(urlPaths, fmt.Sprint(p))
	}

	if strings.HasSuffix(strings.Join(urlPaths, ""), "/") {
		u.Path = path.Join(urlPaths...) + "/"
	} else {
		u.Path = path.Join(urlPaths...)
	}

	joinedURL = u.String()
	return
}

// SetCookie set cookie for context
func SetCookie(cookie http.Cookie, context *qor.Context) {
	cookie.HttpOnly = true

	// set https cookie
	if context.Request != nil && context.Request.URL.Scheme == "https" {
		cookie.Secure = true
	}

	// set default path
	if cookie.Path == "" {
		cookie.Path = "/"
	}

	http.SetCookie(context.Writer, &cookie)
}

// Stringify stringify any data, if it is a struct, will try to use its Name, Title, Code field, else will use its primary key
func Stringify(object interface{}) string {
	if obj, ok := object.(interface {
		Stringify() string
	}); ok {
		return obj.Stringify()
	}

	scope := gorm.Scope{Value: object}
	for _, column := range []string{"Name", "Title", "Code"} {
		if field, ok := scope.FieldByName(column); ok {
			if field.Field.IsValid() {
				result := field.Field.Interface()
				if valuer, ok := result.(driver.Valuer); ok {
					if result, err := valuer.Value(); err == nil {
						return fmt.Sprint(result)
					}
				}
				return fmt.Sprint(result)
			}
		}
	}

	if scope.PrimaryField() != nil {
		if scope.PrimaryKeyZero() {
			return ""
		}
		return fmt.Sprintf("%v#%v", scope.GetModelStruct().ModelType.Name(), scope.PrimaryKeyValue())
	}

	return fmt.Sprint(reflect.Indirect(reflect.ValueOf(object)).Interface())
}

// ModelType get value's model type
func ModelType(value interface{}) reflect.Type {
	reflectType := reflect.Indirect(reflect.ValueOf(value)).Type()

	for reflectType.Kind() == reflect.Ptr || reflectType.Kind() == reflect.Slice {
		reflectType = reflectType.Elem()
	}

	return reflectType
}

// ParseTagOption parse tag options to hash
func ParseTagOption(str string) map[string]string {
	tags := strings.Split(str, ";")
	setting := map[string]string{}
	for _, value := range tags {
		v := strings.Split(value, ":")
		k := strings.TrimSpace(strings.ToUpper(v[0]))
		if len(v) == 2 {
			setting[k] = v[1]
		} else {
			setting[k] = k
		}
	}
	return setting
}

// ExitWithMsg debug error messages and print stack
func ExitWithMsg(msg interface{}, value ...interface{}) {
	fmt.Printf("\n"+filenameWithLineNum()+"\n"+fmt.Sprint(msg)+"\n", value...)
	debug.PrintStack()
}

// FileServer file server that disabled file listing
func FileServer(dir http.Dir) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := path.Join(string(dir), r.URL.Path)
		if f, err := os.Stat(p); err == nil && !f.IsDir() {
			http.ServeFile(w, r, p)
			return
		}

		http.NotFound(w, r)
	})
}

func filenameWithLineNum() string {
	var total = 10
	var results []string
	for i := 2; i < 15; i++ {
		if _, file, line, ok := runtime.Caller(i); ok {
			total--
			results = append(results[:0],
				append(
					[]string{fmt.Sprintf("%v:%v", strings.TrimPrefix(file, os.Getenv("GOPATH")+"src/"), line)},
					results[0:]...)...)

			if total == 0 {
				return strings.Join(results, "\n")
			}
		}
	}
	return ""
}

// GetLocale get locale from request, cookie, after get the locale, will write the locale to the cookie if possible
// Overwrite the default logic with
//
//	utils.GetLocale = func(context *qor.Context) string {
//	    // ....
//	}
var GetLocale = func(context *qor.Context) string {
	if locale := context.Request.Header.Get("Locale"); locale != "" {
		return locale
	}

	if locale := context.Request.URL.Query().Get("locale"); locale != "" {
		if context.Writer != nil {
			context.Request.Header.Set("Locale", locale)
			SetCookie(http.Cookie{Name: "locale", Value: locale, Expires: time.Now().AddDate(1, 0, 0)}, context)
		}
		return locale
	}

	if locale, err := context.Request.Cookie("locale"); err == nil {
		return locale.Value
	}

	return ""
}

// ParseTime parse time from string
// Overwrite the default logic with
//
//	utils.ParseTime = func(timeStr string, context *qor.Context) (time.Time, error) {
//	    // ....
//	}
var ParseTime = func(timeStr string, context *qor.Context) (time.Time, error) {
	return now.Parse(timeStr)
}

// FormatTime format time to string
// Overwrite the default logic with
//
//	utils.FormatTime = func(time time.Time, format string, context *qor.Context) string {
//	    // ....
//	}
var FormatTime = func(date time.Time, format string, context *qor.Context) string {
	return date.Format(format)
}

var replaceIdxRegexp = regexp.MustCompile(`\[\d+\]`)

// SortFormKeys sort form keys
func SortFormKeys(strs []string) {
	sort.Slice(strs, func(i, j int) bool { // true for first
		str1 := strs[i]
		str2 := strs[j]
		matched1 := replaceIdxRegexp.FindAllStringIndex(str1, -1)
		matched2 := replaceIdxRegexp.FindAllStringIndex(str2, -1)

		for x := 0; x < len(matched1); x++ {
			prefix1 := str1[:matched1[x][0]]
			prefix2 := str2

			if len(matched2) >= x+1 {
				prefix2 = str2[:matched2[x][0]]
			}

			if prefix1 != prefix2 {
				return strings.Compare(prefix1, prefix2) < 0
			}

			if len(matched2) < x+1 {
				return false
			}

			number1 := str1[matched1[x][0]:matched1[x][1]]
			number2 := str2[matched2[x][0]:matched2[x][1]]

			if number1 != number2 {
				if len(number1) != len(number2) {
					return len(number1) < len(number2)
				}
				return strings.Compare(number1, number2) < 0
			}
		}

		return strings.Compare(str1, str2) < 0
	})
}

// GetAbsURL get absolute URL from request, refer: https://stackoverflow.com/questions/6899069/why-are-request-url-host-and-scheme-blank-in-the-development-server
func GetAbsURL(req *http.Request) url.URL {
	if req.URL.IsAbs() {
		return *req.URL
	}

	var result *url.URL
	if domain := req.Header.Get("Origin"); domain != "" {
		result, _ = url.Parse(domain)
	} else {
		if req.TLS == nil {
			result, _ = url.Parse("http://" + req.Host)
		} else {
			result, _ = url.Parse("https://" + req.Host)
		}
	}

	result.Parse(req.RequestURI)
	return *result
}

// Indirect returns last value that v points to
func Indirect(v reflect.Value) reflect.Value {
	for v.Kind() == reflect.Ptr {
		v = reflect.Indirect(v)
	}
	return v
}

// SliceUniq removes duplicate values in given slice
func SliceUniq(s []string) []string {
	for i := 0; i < len(s); i++ {
		for i2 := i + 1; i2 < len(s); i2++ {
			if s[i] == s[i2] {
				// delete
				s = append(s[:i2], s[i2+1:]...)
				i2--
			}
		}
	}
	return s
}

// SafeJoin safe join https://snyk.io/research/zip-slip-vulnerability#go
func SafeJoin(paths ...string) (string, error) {
	result := path.Join(paths...)
	// check filepath
	if !strings.HasPrefix(result, filepath.Clean(paths[0])+string(os.PathSeparator)) {
		return "", errors.New("invalid filepath")
	}

	return result, nil
}

// func ModelStructs(modelStruct interface{}) *admin.Section {
// 	section := &admin.Section{}
// 	scope := DefaultAdmin.NewScope(modelStruct)
// 	results := reflect.New(reflect.SliceOf(scope.GetModelStruct().Type)).Interface()

// 	DefaultAdmin.DB.Find(results)
// 	section.Rows = [][]*admin.Section{{{
// 		Struct: modelStruct,
// 		Label:  "Result",
// 	}}}
// 	for _, record := range reflect.ValueOf(results).Elem().Slice() {
// 		section.Rows[0] = append(section.Rows[0], &admin.Section{Struct: record.Interface()})
// 	}
// 	return section
// }

// ToArray get array from value, will ignore blank string to convert it to array
func ToArray(value interface{}) (values []string) {
	switch value := value.(type) {
	case []string:
		values = []string{}
		for _, v := range value {
			if v != "" {
				values = append(values, v)
			}
		}
	case []interface{}:
		for _, v := range value {
			values = append(values, fmt.Sprint(v))
		}
	default:
		if value := fmt.Sprint(value); value != "" {
			values = []string{value}
		}
	}
	return
}

// ToString get string from value, if passed value is a slice, will use the first element
func ToString(value interface{}) string {
	if v, ok := value.([]string); ok {
		for _, s := range v {
			if s != "" {
				return s
			}
		}
		return ""
	} else if v, ok := value.(string); ok {
		return v
	} else if v, ok := value.([]interface{}); ok {
		for _, s := range v {
			if fmt.Sprint(s) != "" {
				return fmt.Sprint(s)
			}
		}
		return ""
	}
	return fmt.Sprintf("%v", value)
}

// ToInt get int from value, if passed value is empty string, result will be 0
func ToInt(value interface{}) int64 {
	if result := ToString(value); result == "" {
		return 0
	} else if i, err := strconv.ParseInt(result, 10, 64); err == nil {
		return i
	} else {
		panic("failed to parse int: " + result)
	}
}

// ToUint get uint from value, if passed value is empty string, result will be 0
func ToUint(value interface{}) uint64 {
	if result := ToString(value); result == "" {
		return 0
	} else if i, err := strconv.ParseUint(result, 10, 64); err == nil {
		return i
	} else {
		panic("failed to parse uint: " + result)
	}
}

// ToFloat get float from value, if passed value is empty string, result will be 0
func ToFloat(value interface{}) float64 {

	if result := ToString(value); result == "" || result == "NaN" {
		return 0
	} else if i, err := strconv.ParseFloat(result, 64); err == nil {
		return i
	} else {
		return 0
	}
}

// GetParm 获取Parms参数
func GetParm(urls, parmname string) string {
	parm, _ := regexp.Compile("(^|&)" + parmname + "=([^&]*)(&|$)")
	parms := parm.FindAllSubmatch([]byte(urls), -1)
	if len(parms) > 0 {
		return string(parms[0][1])
	} else {
		return ""
	}
}

// 截取字符串 start 起点下标 length 需要截取的长度
func SubString(str string, start int, length int) string {
	rs := []rune(str)
	rl := len(rs)
	end := 0

	if start < 0 {
		start = rl - 1 + start
	}
	end = start + length

	if start > end {
		start, end = end, start
	}

	if start < 0 {
		start = 0
	}
	if start > rl {
		start = rl
	}
	if end < 0 {
		end = 0
	}
	if end > rl {
		end = rl
	}

	return string(rs[start:end])
}

func ParseBool(str string) bool {
	switch str {
	case "1", "t", "T", "true", "TRUE", "True":
		return true
	case "0", "f", "F", "false", "FALSE", "False":
		return false
	}
	return false
}

func FormatBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ToDateTime 转换为日期时间
func ToDateTime(timestamp int64) time.Time {

	tm := time.Unix(timestamp, 0)

	//2021-03-25T16:28:46Z
	//	var timeLayoutStr = "2006-01-02 15:04:05" //go中的时间格式化必须是这个时间
	//ts, _ := time.Parse(timeLayoutStr, ToString(value))

	//stamp, _ := time.ParseInLocation(timeLayoutStr, ToString(value), time.Local)
	return tm
}
