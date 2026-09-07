package envschema

import (
	"bytes"
	"cmp"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math"
	"math/big"
	"mime"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	duration "github.com/depthbomb/duration"
)

// LookupFunc returns the text and presence of an environment name. Implementations must return stable results during a
// load operation.
type LookupFunc func(string) (string, bool)

// Values contains parsed values indexed by their primary environment names.
type Values map[string]any

// SecretValue stores sensitive text and redacts every formatting and marshaling path.
type SecretValue struct {
	value string
}

// PublicKeyValue wraps a parsed public key.
type PublicKeyValue struct {
	key any
}

type semanticVersion struct {
	major      uint64
	minor      uint64
	patch      uint64
	prerelease []string
}

const redactedSecret = "[redacted]"

var (
	bytesPattern  = regexp.MustCompile(`(?i)^(\d+(?:\.\d+)?|\.\d+)\s*(B|KB|MB|GB|TB|KIB|MIB|GIB|TIB)?$`)
	uuidPattern   = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab0-9][0-9a-f]{3}-[0-9a-f]{12}$`)
	hexPattern    = regexp.MustCompile(`(?i)^[0-9a-f]+$`)
	semVerPattern = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	ulidPattern   = regexp.MustCompile(`(?i)^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
)

func lookupOS(name string) (string, bool) {
	return os.LookupEnv(name)
}

func parseVariable(rule Rule, name string, fallbacks []string, lookup LookupFunc) (any, bool, error) {
	rawValue, exists := lookup(name)
	for index := 0; !exists && index < len(fallbacks); index++ {
		rawValue, exists = lookup(fallbacks[index])
	}

	var raw any = rawValue
	if !exists || rawValue == "" && !rule.EmptyAllowed {
		if !rule.HasDefault {
			if rule.Required {
				return nil, false, fmt.Errorf("environment variable %q is required but not defined", name)
			}

			return nil, false, nil
		}
		raw = rule.Default
	}

	value, err := parseRule(rule, raw, name)
	if err != nil {
		return nil, false, err
	}

	return value, true, nil
}

func parseRule(rule Rule, raw any, path string) (any, error) {
	value, err := parseRuleValue(rule, raw, path)
	if err != nil {
		return nil, err
	}
	if rule.Kind == KindMap {
		if err := checkMapKeys(rule, value, path); err != nil {
			return nil, err
		}
	}
	if err := checkDecimalShape(rule, value, path); err != nil {
		return nil, err
	}
	if err := checkExactPolicies(rule, value, path); err != nil {
		return nil, err
	}

	return value, nil
}

func parseRuleValue(rule Rule, raw any, path string) (any, error) {
	switch rule.Kind {
	case KindString:
		return parseString(rule, raw, path)
	case KindNumber, KindFloat:
		return parseNumber(rule, raw, path, false)
	case KindInt:
		return parseNumber(rule, raw, path, true)
	case KindUInt:
		return parseUint(rule, raw, path)
	case KindBoolean:
		return parseBoolean(rule, raw, path)
	case KindEnum:
		return parseEnum(rule, raw, path)
	case KindJSON:
		return parseJSON(rule, raw, path)
	case KindArray:
		return parseArray(rule, raw, path)
	case KindList:
		return parseList(rule, raw, path)
	case KindDuration:
		return parseDuration(rule, raw, path)
	case KindDate:
		return parseDate(rule, raw, path)
	case KindBytes:
		return parseBytes(rule, raw, path)
	case KindPath:
		return parsePath(rule, raw, path)
	case KindBase64:
		return parseBase64(rule, raw, path)
	case KindSecret:
		value, err := parseString(rule, raw, path)
		if err != nil {
			return nil, err
		}

		return SecretValue{value: value.(string)}, nil
	case KindEmail:
		return parseEmail(raw, path)
	case KindPort:
		return parsePort(rule, raw, path)
	case KindURL:
		return parseURLRule(rule, raw, path)
	case KindHost:
		return parseHost(rule, raw, path)
	case KindUUID:
		return parseUUID(rule, raw, path)
	case KindIP:
		return parseIP(rule, raw, path)
	case KindHash:
		return parseHash(rule, raw, path)
	case KindHex:
		return parseHex(rule, raw, path)
	case KindSemVer:
		return parseSemVer(rule, raw, path)
	case KindTimeZone:
		return parseTimeZone(raw, path)
	case KindCIDR:
		return parseCIDR(rule, raw, path)
	case KindEndpoint:
		return parseEndpoint(rule, raw, path)
	case KindUnixSocket:
		return parseUnixSocket(rule, raw, path)
	case KindTimestamp:
		return parseTimestamp(rule, raw, path)
	case KindTimeOfDay:
		return parseTimeOfDay(rule, raw, path)
	case KindMap:
		return parseMap(rule, raw, path)
	case KindRegexp:
		return parseRegexp(raw, path)
	case KindPEM:
		return parsePEM(rule, raw, path)
	case KindCertificate:
		return parseCertificate(rule, raw, path)
	case KindPrivateKey:
		return parsePrivateKey(rule, raw, path)
	case KindCustom:
		return requireString(raw, path)
	case KindURI:
		return parseURI(rule, raw, path)
	case KindMACAddress:
		return parseMACAddress(raw, path)
	case KindPublicKey:
		return parsePublicKey(rule, raw, path)
	case KindCertBundle:
		return parseCertificateBundle(rule, raw, path)
	case KindBigInt:
		return parseBigInt(rule, raw, path)
	case KindDecimal:
		return parseDecimal(rule, raw, path)
	case KindMediaType:
		return parseMediaType(rule, raw, path)
	case KindFileMode:
		return parseFileMode(raw, path)
	case KindULID:
		return parseULID(raw, path)
	case KindGlob:
		return parseGlob(raw, path)
	default:
		return nil, fmt.Errorf("[%s] unsupported rule kind %q", path, rule.Kind)
	}
}

func requireString(raw any, path string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("[%s] expected string but got %T", path, raw)
	}

	return value, nil
}

func parseString(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}

	if rule.Trim {
		value = strings.TrimSpace(value)
	}

	if rule.Pattern != "" {
		compiled, err := compiledPattern(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("[%s] invalid pattern: %w", path, err)
		}
		if !compiled.MatchString(value) {
			return nil, fmt.Errorf("[%s] expected pattern %s", path, rule.Pattern)
		}
	}

	length := len(value)
	if rule.RuneLength {
		length = utf8.RuneCountInString(value)
	}
	if rule.MinLength != nil && length < *rule.MinLength {
		return nil, fmt.Errorf("[%s] expected string length >= %d but got %d", path, *rule.MinLength, length)
	}

	if rule.MaxLength != nil && length > *rule.MaxLength {
		return nil, fmt.Errorf("[%s] expected string length <= %d but got %d", path, *rule.MaxLength, length)
	}
	if rule.Prefix != "" && !strings.HasPrefix(value, rule.Prefix) {
		return nil, fmt.Errorf("[%s] expected prefix %q", path, rule.Prefix)
	}
	if rule.Suffix != "" && !strings.HasSuffix(value, rule.Suffix) {
		return nil, fmt.Errorf("[%s] expected suffix %q", path, rule.Suffix)
	}
	for _, character := range value {
		if rule.ASCII && character > 127 {
			return nil, fmt.Errorf("[%s] expected ASCII text", path)
		}
		if rule.Printable && !unicode.IsPrint(character) {
			return nil, fmt.Errorf("[%s] expected printable text", path)
		}
		if rule.NoWhitespace && unicode.IsSpace(character) {
			return nil, fmt.Errorf("[%s] expected text without whitespace", path)
		}
	}
	if rule.Lowercase && strings.ToLower(value) != value {
		return nil, fmt.Errorf("[%s] expected lowercase text", path)
	}
	if rule.Uppercase && strings.ToUpper(value) != value {
		return nil, fmt.Errorf("[%s] expected uppercase text", path)
	}
	if rule.NoSurroundingSpace && strings.TrimSpace(value) != value {
		return nil, fmt.Errorf("[%s] expected no surrounding whitespace", path)
	}
	if _, required := policy(rule, policyUTF8); required && !utf8.ValidString(value) {
		return nil, fmt.Errorf("[%s] expected valid UTF-8", path)
	}
	if _, required := policy(rule, policySingleLine); required && strings.ContainsAny(value, "\r\n") {
		return nil, fmt.Errorf("[%s] expected one line", path)
	}
	if _, required := policy(rule, policyNoControl); required {
		for _, character := range value {
			if unicode.IsControl(character) {
				return nil, fmt.Errorf("[%s] expected text without control characters", path)
			}
		}
	}
	if expected, required := policy(rule, policyEqualFold); required && !strings.EqualFold(value, expected[0]) {
		return nil, fmt.Errorf("[%s] expected text equal to %q ignoring case", path, expected[0])
	}
	if required, exists := policy(rule, policyContaining); exists {
		for _, fragment := range required {
			if !strings.Contains(value, fragment) {
				return nil, fmt.Errorf("[%s] expected text containing %q", path, fragment)
			}
		}
	}
	if forbidden, exists := policy(rule, policyNotContaining); exists {
		for _, fragment := range forbidden {
			if strings.Contains(value, fragment) {
				return nil, fmt.Errorf("[%s] expected text without %q", path, fragment)
			}
		}
	}

	return value, nil
}

func parseNumber(rule Rule, raw any, path string, integer bool) (any, error) {
	if integer {
		return parseInteger(rule, raw, path)
	}

	var value float64
	switch raw := raw.(type) {
	case float64:
		value = raw
	case float32:
		value = float64(raw)
	case int:
		value = float64(raw)
	case int64:
		value = float64(raw)
	case json.Number:
		parsed, err := raw.Float64()
		if err != nil {
			return nil, fmt.Errorf("[%s] expected number: %w", path, err)
		}
		value = parsed
	case string:
		trimmed := strings.TrimSpace(raw)
		parsed, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return nil, fmt.Errorf("[%s] expected number but got %q", path, raw)
		}

		value = parsed
	default:
		return nil, fmt.Errorf("[%s] expected number but got %T", path, raw)
	}

	if math.IsInf(value, 0) || math.IsNaN(value) {
		return nil, fmt.Errorf("[%s] expected finite number", path)
	}

	if err := checkNumericConstraints(rule, value, path, "number"); err != nil {
		return nil, err
	}

	return value, nil
}

func parseInteger(rule Rule, raw any, path string) (any, error) {
	var value int64
	switch raw := raw.(type) {
	case int:
		value = int64(raw)
	case int64:
		value = raw
	case float32:
		return parseInteger(rule, float64(raw), path)
	case float64:
		if math.IsNaN(raw) || raw < -0x1p63 || raw >= 0x1p63 || math.Trunc(raw) != raw {
			return nil, fmt.Errorf("[%s] expected integer in int64 range", path)
		}
		value = int64(raw)
	case json.Number:
		// A JSON number is already numeric; Base applies only to text input.
		numericRule := rule
		numericRule.Policies = nil

		return parseInteger(numericRule, raw.String(), path)
	case string:
		trimmed := strings.TrimSpace(raw)
		base, configured := policyInt(rule, policyBase)
		if !configured {
			base = 10
		}
		parsed, err := strconv.ParseInt(trimmed, base, 64)
		if err != nil {
			// Preserve integral decimal and exponent forms without rounding through float64.
			floating, floatErr := strconv.ParseFloat(trimmed, 64)
			if configured || floatErr != nil || math.IsNaN(floating) || math.IsInf(floating, 0) {
				return nil, fmt.Errorf("[%s] expected integer in int64 range", path)
			}
			exact, ok := new(big.Rat).SetString(trimmed)
			if !ok || !exact.IsInt() || !exact.Num().IsInt64() {
				return nil, fmt.Errorf("[%s] expected integer in int64 range", path)
			}
			parsed = exact.Num().Int64()
		}
		value = parsed
	default:
		return nil, fmt.Errorf("[%s] expected integer but got %T", path, raw)
	}

	if value >= -(1<<53) && value <= 1<<53 {
		if err := checkNumericConstraints(rule, float64(value), path, "integer"); err != nil {
			return nil, err
		}
	} else if _, err := validateBigInt(rule, *big.NewInt(value), path); err != nil {
		return nil, err
	}

	return value, nil
}

func parseUint(rule Rule, raw any, path string) (any, error) {
	var value uint64
	switch raw := raw.(type) {
	case uint64:
		value = raw
	case uint:
		value = uint64(raw)
	case int:
		if raw < 0 {
			return nil, fmt.Errorf("[%s] expected unsigned integer", path)
		}

		value = uint64(raw)
	case int64:
		if raw < 0 {
			return nil, fmt.Errorf("[%s] expected unsigned integer", path)
		}

		value = uint64(raw)
	case float64:
		if raw < 0 || math.Trunc(raw) != raw || raw >= 0x1p64 {
			return nil, fmt.Errorf("[%s] expected unsigned integer", path)
		}

		value = uint64(raw)
	case json.Number:
		parsed, err := strconv.ParseUint(raw.String(), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("[%s] expected unsigned integer", path)
		}

		value = parsed
	case string:
		base := 10
		if configured, exists := policyInt(rule, policyBase); exists {
			base = configured
		}

		parsed, err := strconv.ParseUint(strings.TrimSpace(raw), base, 64)
		if err != nil {
			return nil, fmt.Errorf("[%s] expected unsigned integer but got %q", path, raw)
		}

		value = parsed
	default:
		return nil, fmt.Errorf("[%s] expected unsigned integer but got %T", path, raw)
	}

	if value <= 1<<53 {
		if err := checkNumericConstraints(rule, float64(value), path, "unsigned integer"); err != nil {
			return nil, err
		}
	} else if _, err := validateBigInt(rule, *new(big.Int).SetUint64(value), path); err != nil {
		return nil, err
	}

	return value, nil
}

func checkBounds(rule Rule, value float64, path string, label string) error {
	if rule.Min != nil && value < *rule.Min {
		return fmt.Errorf("[%s] expected %s >= %v but got %v", path, label, *rule.Min, value)
	}

	if rule.Max != nil && value > *rule.Max {
		return fmt.Errorf("[%s] expected %s <= %v but got %v", path, label, *rule.Max, value)
	}

	return nil
}

func checkNumericConstraints(rule Rule, value float64, path string, label string) error {
	if rule.Positive && value <= 0 {
		return fmt.Errorf("[%s] expected positive %s", path, label)
	}
	if rule.Negative && value >= 0 {
		return fmt.Errorf("[%s] expected negative %s", path, label)
	}
	if err := checkBounds(rule, value, path, label); err != nil {
		return err
	}
	if rule.ExclusiveMin != nil && value <= *rule.ExclusiveMin {
		return fmt.Errorf("[%s] expected %s > %v", path, label, *rule.ExclusiveMin)
	}
	if rule.ExclusiveMax != nil && value >= *rule.ExclusiveMax {
		return fmt.Errorf("[%s] expected %s < %v", path, label, *rule.ExclusiveMax)
	}
	if rule.RejectZero && value == 0 {
		return fmt.Errorf("[%s] expected non-zero %s", path, label)
	}
	if rule.Multiple != nil && math.Abs(value / *rule.Multiple - math.Round(value / *rule.Multiple)) > 1e-9 {
		return fmt.Errorf("[%s] expected %s to be a multiple of %v", path, label, *rule.Multiple)
	}

	return nil
}

func parseBoolean(rule Rule, raw any, path string) (any, error) {
	if value, ok := raw.(bool); ok {
		return value, nil
	}

	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}

	normalized := strings.ToLower(strings.TrimSpace(value))
	if values, configured := policy(rule, policyTrueValues); configured {
		for _, candidate := range values {
			if strings.EqualFold(normalized, candidate) {
				return true, nil
			}
		}
	}
	if values, configured := policy(rule, policyFalseValues); configured {
		for _, candidate := range values {
			if strings.EqualFold(normalized, candidate) {
				return false, nil
			}
		}
	}

	switch normalized {
	case "true", "1", "yes", "y", "on", "enabled":
		if rule.StrictBoolean && !strings.EqualFold(strings.TrimSpace(value), "true") {
			break
		}

		return true, nil
	case "false", "0", "no", "n", "off", "disabled":
		if rule.StrictBoolean && !strings.EqualFold(strings.TrimSpace(value), "false") {
			break
		}

		return false, nil
	}

	return nil, fmt.Errorf("[%s] expected boolean but got %q", path, value)
}

func parseEnum(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}

	comparison := value
	if rule.EnumCaseInsensitive {
		comparison = strings.ToLower(value)
	}

	for alias, canonical := range rule.Aliases {
		candidate := alias
		if rule.EnumCaseInsensitive {
			candidate = strings.ToLower(alias)
		}
		if comparison == candidate {
			value = canonical
			comparison = canonical

			if rule.EnumCaseInsensitive {
				comparison = strings.ToLower(canonical)
			}
			break
		}
	}
	for _, choice := range rule.Choices {
		candidate := choice
		if rule.EnumCaseInsensitive {
			candidate = strings.ToLower(choice)
		}

		if comparison == candidate {
			return choice, nil
		}
	}

	return nil, fmt.Errorf("[%s] expected one of [%s] but got %q", path, strings.Join(rule.Choices, ", "), value)
}

func parseJSON(rule Rule, raw any, path string) (any, error) {
	if value, ok := raw.(json.RawMessage); ok {
		if len(rule.Policies) == 0 && !json.Valid(value) {
			return nil, fmt.Errorf("[%s] expected valid JSON", path)
		}
		if len(rule.Policies) != 0 {
			if err := validateJSONPolicies(rule, value, path); err != nil {
				return nil, err
			}
		}

		return append(json.RawMessage(nil), value...), nil
	}

	value, err := requireString(raw, path)
	if err != nil {
		encoded, marshalErr := json.Marshal(raw)
		if marshalErr != nil {
			return nil, err
		}

		if len(rule.Policies) != 0 {
			if policyErr := validateJSONPolicies(rule, encoded, path); policyErr != nil {
				return nil, policyErr
			}
		}

		return json.RawMessage(encoded), nil
	}

	encoded := []byte(value)
	if len(rule.Policies) == 0 && !json.Valid(encoded) {
		return nil, fmt.Errorf("[%s] expected valid JSON", path)
	}

	if len(rule.Policies) != 0 {
		if err := validateJSONPolicies(rule, encoded, path); err != nil {
			return nil, err
		}
	}

	return json.RawMessage(value), nil
}

func jsonValueDepth(value any) int {
	maximum := 1

	switch value := value.(type) {
	case []any:
		for _, item := range value {
			maximum = max(maximum, 1+jsonValueDepth(item))
		}
	case map[string]any:
		for _, item := range value {
			maximum = max(maximum, 1+jsonValueDepth(item))
		}
	}

	return maximum
}

type jsonObjectKey struct {
	raw     []byte
	decoded string
}

func skipJSONWhitespace(encoded []byte, index int) int {
	for index < len(encoded) {
		switch encoded[index] {
		case ' ', '\t', '\r', '\n':
			index++
		default:
			return index
		}
	}

	return index
}

func scanJSONString(encoded []byte, index int) (int, bool) {
	escaped := false
	for index++; encoded[index] != '"'; index++ {
		if encoded[index] == '\\' {
			escaped = true
			index++
		}
	}

	return index + 1, escaped
}

func jsonKeysEqual(left jsonObjectKey, right jsonObjectKey) bool {
	if left.decoded == "" && right.decoded == "" {
		return bytes.Equal(left.raw, right.raw)
	}

	leftValue := left.decoded
	if leftValue == "" {
		leftValue = string(left.raw)
	}

	rightValue := right.decoded
	if rightValue == "" {
		rightValue = string(right.raw)
	}

	return leftValue == rightValue
}

func jsonKeyString(key jsonObjectKey) string {
	if key.decoded != "" {
		return key.decoded
	}

	return string(key.raw)
}

func scanUniqueJSONValue(encoded []byte, index int) (int, error) {
	index = skipJSONWhitespace(encoded, index)
	switch encoded[index] {
	case '"':
		end, _ := scanJSONString(encoded, index)

		return end, nil
	case '[':
		index = skipJSONWhitespace(encoded, index+1)
		for encoded[index] != ']' {
			var err error
			index, err = scanUniqueJSONValue(encoded, index)
			if err != nil {
				return 0, err
			}

			index = skipJSONWhitespace(encoded, index)
			if encoded[index] == ',' {
				index = skipJSONWhitespace(encoded, index+1)
			}
		}

		return index + 1, nil
	case '{':
		var keys [16]jsonObjectKey
		var overflow map[string]struct{}

		count := 0

		index = skipJSONWhitespace(encoded, index+1)
		for encoded[index] != '}' {
			start := index
			end, escaped := scanJSONString(encoded, start)
			key := jsonObjectKey{raw: encoded[start+1 : end-1]}

			if escaped || !utf8.Valid(key.raw) {
				if err := json.Unmarshal(encoded[start:end], &key.decoded); err != nil {
					return 0, err
				}
			}
			if count < len(keys) {
				for prior := 0; prior < count; prior++ {
					if jsonKeysEqual(keys[prior], key) {
						return 0, fmt.Errorf("duplicate object key")
					}
				}

				keys[count] = key
			} else {
				if overflow == nil {
					overflow = make(map[string]struct{}, len(keys)+1)
					for _, prior := range keys {
						overflow[jsonKeyString(prior)] = struct{}{}
					}
				}
				keyString := jsonKeyString(key)
				if _, exists := overflow[keyString]; exists {
					return 0, fmt.Errorf("duplicate object key")
				}

				overflow[keyString] = struct{}{}
			}

			count++

			index = skipJSONWhitespace(encoded, end)
			index = skipJSONWhitespace(encoded, index+1)

			var err error
			index, err = scanUniqueJSONValue(encoded, index)
			if err != nil {
				return 0, err
			}

			index = skipJSONWhitespace(encoded, index)
			if encoded[index] == ',' {
				index = skipJSONWhitespace(encoded, index+1)
			}
		}

		return index + 1, nil
	default:
		for index < len(encoded) {
			switch encoded[index] {
			case ',', '}', ']', ' ', '\t', '\r', '\n':
				return index, nil
			default:
				index++
			}
		}

		return index, nil
	}
}

func validateJSONPolicies(rule Rule, encoded []byte, path string) error {
	if maximum, configured := policyInt(rule, policyJSONSize); configured && len(encoded) > maximum {
		return fmt.Errorf("[%s] expected JSON no larger than %d bytes", path, maximum)
	}

	var value any
	if err := json.Unmarshal(encoded, &value); err != nil {
		return fmt.Errorf("[%s] expected valid JSON", path)
	}

	if kinds, configured := policy(rule, policyJSONKind); configured {
		for _, kind := range kinds {
			valid := false
			switch kind {
			case "object":
				_, valid = value.(map[string]any)
			case "array":
				_, valid = value.([]any)
			case "scalar":
				switch value.(type) {
				case map[string]any, []any:
				default:
					valid = true
				}
			case "nonNull":
				valid = value != nil
			}

			if !valid {
				return fmt.Errorf("[%s] expected JSON kind %s", path, kind)
			}
		}
	}
	if maximum, configured := policyInt(rule, policyJSONDepth); configured && jsonValueDepth(value) > maximum {
		return fmt.Errorf("[%s] expected JSON depth <= %d", path, maximum)
	}

	object, isObject := value.(map[string]any)

	if keys, configured := policy(rule, policyRequiredKeys); configured {
		if !isObject {
			return fmt.Errorf("[%s] expected JSON object for required keys", path)
		}
		for _, key := range keys {
			if _, exists := object[key]; !exists {
				return fmt.Errorf("[%s] expected JSON key %q", path, key)
			}
		}
	}

	if keys, configured := policy(rule, policyAllowedKeys); configured {
		for key := range object {
			allowed := slices.Contains(keys, key)
			if !allowed {
				return fmt.Errorf("[%s] unexpected JSON key %q", path, key)
			}
		}
	}

	if _, required := policy(rule, policyJSONUniqueKeys); required {
		if _, err := scanUniqueJSONValue(encoded, 0); err != nil {
			return fmt.Errorf("[%s] expected unique JSON object keys: %w", path, err)
		}
	}

	return nil
}

func parseArray(rule Rule, raw any, path string) (any, error) {
	var items []any
	switch raw := raw.(type) {
	case string:
		trimmed := strings.TrimSpace(raw)
		if len(trimmed) == 0 || trimmed[0] != '[' || !json.Valid([]byte(trimmed)) {
			return nil, fmt.Errorf("[%s] expected valid JSON array", path)
		}
		decoder := json.NewDecoder(strings.NewReader(trimmed))
		decoder.UseNumber()
		if err := decoder.Decode(&items); err != nil {
			return nil, fmt.Errorf("[%s] expected valid JSON array", path)
		}
	case []any:
		items = raw
	default:
		return nil, fmt.Errorf("[%s] expected array but got %T", path, raw)
	}

	if err := checkItemCount(rule, len(items), path); err != nil {
		return nil, err
	}

	return parseItems(*rule.Item, items, path, rule.Unique)
}

func parseList(rule Rule, raw any, path string) (any, error) {
	var items []any
	switch raw := raw.(type) {
	case string:
		separator := rule.Separator
		if separator == "" {
			separator = ","
		}

		var parts []string
		if _, configured := policy(rule, policyCSV); configured {
			records, err := csv.NewReader(strings.NewReader(raw)).ReadAll()
			if err != nil || len(records) != 1 {
				return nil, fmt.Errorf("[%s] expected one CSV record", path)
			}

			parts = records[0]
		} else {
			parts = strings.Split(raw, separator)
		}

		for index := range parts {
			if rule.ListTrim {
				parts[index] = strings.TrimSpace(parts[index])
			}
		}

		if err := checkItemCount(rule, len(parts), path); err != nil {
			return nil, err
		}

		if canReuseStringItems(*rule.Item, rule.Unique) {
			if err := validateCollectionPolicies(rule, parts, path); err != nil {
				return nil, err
			}

			return parts, nil
		}

		items = make([]any, len(parts))

		for index := range parts {
			items[index] = parts[index]
		}
	case []any:
		items = raw
	default:
		return nil, fmt.Errorf("[%s] expected delimited list but got %T", path, raw)
	}

	if err := checkItemCount(rule, len(items), path); err != nil {
		return nil, err
	}

	parsed, err := parseItems(*rule.Item, items, path, rule.Unique)
	if err != nil {
		return nil, err
	}

	if err := validateCollectionPolicies(rule, parsed, path); err != nil {
		return nil, err
	}

	return parsed, nil
}

func validateCollectionPolicies(rule Rule, parsed any, path string) error {
	if items, stringsOnly := parsed.([]string); stringsOnly {
		return validateStringCollectionPolicies(rule, items, path)
	}

	_, rejectEmpty := policy(rule, policyRejectEmptyItems)
	_, caseFoldConfigured := policy(rule, policyCaseFoldUnique)
	_, distinctConfigured := policy(rule, policyDistinctMin)
	_, sortedConfigured := policy(rule, policySorted)

	if !rejectEmpty && !caseFoldConfigured && !distinctConfigured && !sortedConfigured {
		return nil
	}

	items := reflect.ValueOf(parsed)

	if rejectEmpty {
		for index := 0; index < items.Len(); index++ {
			item, stringItem := items.Index(index).Interface().(string)
			if stringItem && item == "" {
				return fmt.Errorf("[%s] expected non-empty item at index %d", path, index)
			}
		}
	}

	distinctCount := 0

	if caseFoldConfigured || distinctConfigured {
		seenComparable := make(map[any]struct{}, items.Len())
		seenEncoded := make(map[string]struct{})
		for index := 0; index < items.Len(); index++ {
			item := items.Index(index).Interface()
			if caseFoldConfigured {
				item = strings.ToLower(item.(string))
			}
			itemType := reflect.TypeOf(item)
			exists := false
			if itemType != nil && itemType.Comparable() {
				_, exists = seenComparable[item]
				seenComparable[item] = struct{}{}
			} else {
				encoded, _ := json.Marshal(item)
				key := string(encoded)
				_, exists = seenEncoded[key]
				seenEncoded[key] = struct{}{}
			}
			if exists && caseFoldConfigured {
				return fmt.Errorf("[%s] expected case-insensitively unique items", path)
			}
			if !exists {
				distinctCount++
			}
		}
	}

	if minimum, configured := policyInt(rule, policyDistinctMin); configured && distinctCount < minimum {
		return fmt.Errorf("[%s] expected at least %d distinct items", path, minimum)
	}

	if order, configured := policy(rule, policySorted); configured {
		for index := 1; index < items.Len(); index++ {
			comparison, comparable := compareOrderedValues(items.Index(index-1).Interface(), items.Index(index).Interface())
			if !comparable {
				return fmt.Errorf("[%s] items do not have a defined order", path)
			}
			if comparison > 0 || order[0] == "strict" && comparison == 0 {
				return fmt.Errorf("[%s] expected sorted items", path)
			}
		}
	}

	return nil
}

func validateStringCollectionPolicies(rule Rule, items []string, path string) error {
	_, rejectEmpty := policy(rule, policyRejectEmptyItems)
	_, caseFold := policy(rule, policyCaseFoldUnique)
	minimum, countDistinct := policyInt(rule, policyDistinctMin)
	order, sorted := policy(rule, policySorted)
	if !rejectEmpty && !caseFold && !countDistinct && !sorted {
		return nil
	}
	if rejectEmpty {
		for index, item := range items {
			if item == "" {
				return fmt.Errorf("[%s] expected non-empty item at index %d", path, index)
			}
		}
	}
	if caseFold || countDistinct {
		distinct := make(map[string]struct{}, len(items))
		for _, item := range items {
			key := item
			if caseFold {
				key = strings.ToLower(key)
			}
			if _, exists := distinct[key]; exists && caseFold {
				return fmt.Errorf("[%s] expected case-insensitively unique items", path)
			}
			distinct[key] = struct{}{}
		}
		if countDistinct && len(distinct) < minimum {
			return fmt.Errorf("[%s] expected at least %d distinct items", path, minimum)
		}
	}
	if sorted {
		for index := 1; index < len(items); index++ {
			comparison := strings.Compare(items[index-1], items[index])
			if comparison > 0 || order[0] == "strict" && comparison == 0 {
				return fmt.Errorf("[%s] expected sorted items", path)
			}
		}
	}

	return nil
}

func compareOrderedValues(left any, right any) (int, bool) {
	if leftString, ok := left.(string); ok {
		rightString, rightOK := right.(string)
		if !rightOK {
			return 0, false
		}

		return strings.Compare(leftString, rightString), true
	}
	if comparison, comparable := compareConstraintValues(left, right); comparable {
		return comparison, true
	}
	leftValue := reflect.ValueOf(left)
	rightValue := reflect.ValueOf(right)
	if leftValue.IsValid() && rightValue.IsValid() && leftValue.Kind() == rightValue.Kind() {
		switch leftValue.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return cmp.Compare(leftValue.Int(), rightValue.Int()), true
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return cmp.Compare(leftValue.Uint(), rightValue.Uint()), true
		}
	}

	return 0, false
}

func checkItemCount(rule Rule, count int, path string) error {
	if rule.MinItems != nil && count < *rule.MinItems {
		return fmt.Errorf("[%s] expected at least %d items", path, *rule.MinItems)
	}

	if rule.MaxItems != nil && count > *rule.MaxItems {
		return fmt.Errorf("[%s] expected at most %d items", path, *rule.MaxItems)
	}

	return nil
}

func canReuseStringItems(rule Rule, unique bool) bool {
	return rule.Kind == KindString && !unique && len(rule.Policies) == 0 && !rule.Trim && rule.Pattern == "" &&
		rule.MinLength == nil && rule.MaxLength == nil && rule.Prefix == "" && rule.Suffix == "" &&
		!rule.ASCII && !rule.Printable && !rule.NoWhitespace && !rule.Lowercase && !rule.Uppercase &&
		!rule.NoSurroundingSpace
}

func parseItems(rule Rule, items []any, path string, unique bool) (any, error) {
	switch rule.Kind {
	case KindString, KindEnum, KindPath, KindBase64, KindEmail, KindURL, KindHost,
		KindUUID, KindIP, KindHash, KindHex, KindSemVer, KindTimeZone, KindEndpoint,
		KindUnixSocket, KindTimeOfDay, KindURI, KindMediaType, KindULID, KindGlob:
		return parseItemsAs[string](rule, items, path, unique)
	case KindNumber, KindFloat:
		return parseItemsAs[float64](rule, items, path, unique)
	case KindInt, KindBytes, KindPort:
		return parseItemsAs[int64](rule, items, path, unique)
	case KindUInt:
		return parseItemsAs[uint64](rule, items, path, unique)
	case KindBoolean:
		return parseItemsAs[bool](rule, items, path, unique)
	case KindDuration:
		return parseItemsAs[time.Duration](rule, items, path, unique)
	case KindDate, KindTimestamp:
		return parseItemsAs[time.Time](rule, items, path, unique)
	case KindCIDR:
		return parseItemsAs[netip.Prefix](rule, items, path, unique)
	case KindRegexp:
		return parseItemsAs[*regexp.Regexp](rule, items, path, unique)
	case KindPEM:
		return parseItemsAs[[]byte](rule, items, path, unique)
	case KindCertificate:
		return parseItemsAs[*x509.Certificate](rule, items, path, unique)
	case KindPrivateKey:
		return parseItemsAs[SecretValue](rule, items, path, unique)
	case KindJSON:
		return parseItemsAs[json.RawMessage](rule, items, path, unique)
	case KindSecret:
		return parseItemsAs[SecretValue](rule, items, path, unique)
	case KindMACAddress:
		return parseItemsAs[net.HardwareAddr](rule, items, path, unique)
	case KindPublicKey:
		return parseItemsAs[PublicKeyValue](rule, items, path, unique)
	case KindCertBundle:
		return parseItemsAs[[]*x509.Certificate](rule, items, path, unique)
	case KindBigInt:
		return parseItemsAs[big.Int](rule, items, path, unique)
	case KindDecimal:
		return parseItemsAs[big.Rat](rule, items, path, unique)
	case KindFileMode:
		return parseItemsAs[fs.FileMode](rule, items, path, unique)
	}

	return parseUntypedItems(rule, items, path, unique)
}

func parseItemsAs[T any](rule Rule, items []any, path string, unique bool) ([]T, error) {
	parsed := make([]T, len(items))
	var seenComparable map[any]struct{}
	var seenEncoded map[string]struct{}
	if unique {
		seenComparable = make(map[any]struct{}, len(items))
		seenEncoded = make(map[string]struct{})
	}
	for index, item := range items {
		itemPath := path + "[" + strconv.Itoa(index) + "]"
		value, err := parseRule(rule, item, itemPath)
		if err != nil {
			return nil, err
		}
		parsed[index] = value.(T)

		if unique {
			valueType := reflect.TypeOf(value)
			if valueType != nil && valueType.Comparable() {
				if _, ok := seenComparable[value]; ok {
					return nil, fmt.Errorf("[%s] expected list items to be unique", path)
				}
				seenComparable[value] = struct{}{}
			} else {
				encoded, _ := json.Marshal(value)
				key := string(encoded)
				if _, ok := seenEncoded[key]; ok {
					return nil, fmt.Errorf("[%s] expected list items to be unique", path)
				}
				seenEncoded[key] = struct{}{}
			}
		}
	}

	return parsed, nil
}

func parseUntypedItems(rule Rule, items []any, path string, unique bool) ([]any, error) {
	parsed := make([]any, len(items))
	var seen map[string]struct{}
	if unique {
		seen = make(map[string]struct{}, len(items))
	}
	for index, item := range items {
		itemPath := path + "[" + strconv.Itoa(index) + "]"
		value, err := parseRule(rule, item, itemPath)
		if err != nil {
			return nil, err
		}
		parsed[index] = value

		if unique {
			encoded, _ := json.Marshal(value)
			key := string(encoded)
			if _, ok := seen[key]; ok {
				return nil, fmt.Errorf("[%s] expected list items to be unique", path)
			}
			seen[key] = struct{}{}
		}
	}

	return parsed, nil
}

func parseDuration(rule Rule, raw any, path string) (any, error) {
	var value time.Duration
	switch raw := raw.(type) {
	case json.Number:
		milliseconds, ok := new(big.Rat).SetString(raw.String())
		if !ok {
			return nil, fmt.Errorf("[%s] expected numeric duration", path)
		}
		milliseconds.Mul(milliseconds, new(big.Rat).SetInt64(int64(time.Millisecond)))
		nanoseconds := new(big.Int).Quo(milliseconds.Num(), milliseconds.Denom())
		if !nanoseconds.IsInt64() {
			return nil, fmt.Errorf("[%s] duration is outside time.Duration range", path)
		}
		value = time.Duration(nanoseconds.Int64())
	case time.Duration:
		value = raw
	case string:
		trimmed := strings.TrimSpace(raw)
		if isDecimalNumber(trimmed) {
			milliseconds, err := strconv.ParseFloat(trimmed, 64)
			if err != nil || math.IsInf(milliseconds, 0) || math.IsNaN(milliseconds) {
				return nil, fmt.Errorf("[%s] expected finite duration", path)
			}
			limit := float64(math.MaxInt64) / float64(time.Millisecond)
			if milliseconds > limit || milliseconds < -limit {
				return nil, fmt.Errorf("[%s] duration is outside time.Duration range", path)
			}
			value = time.Duration(milliseconds * float64(time.Millisecond))
		} else {
			parsed, err := duration.Parse(trimmed)
			if err != nil {
				return nil, fmt.Errorf("[%s] expected valid duration: %w", path, err)
			}
			value = parsed.Value()
		}
	case float64:
		value = time.Duration(raw * float64(time.Millisecond))
	case int64:
		value = time.Duration(raw) * time.Millisecond
	default:
		return nil, fmt.Errorf("[%s] expected duration but got %T", path, raw)
	}

	if err := checkNumericConstraints(rule, float64(value)/float64(time.Millisecond), path, "duration in milliseconds"); err != nil {
		return nil, err
	}
	minimum, _ := parseDurationBound(rule.MinDuration)
	if minimum != nil && value < *minimum {
		return nil, fmt.Errorf("[%s] expected duration >= %s", path, rule.MinDuration)
	}
	maximum, _ := parseDurationBound(rule.MaxDuration)
	if maximum != nil && value > *maximum {
		return nil, fmt.Errorf("[%s] expected duration <= %s", path, rule.MaxDuration)
	}

	return value, nil
}

func isDecimalNumber(value string) bool {
	if value == "" {
		return false
	}

	digits := 0
	dots := 0
	for index, character := range value {
		switch {
		case character >= '0' && character <= '9':
			digits++
		case character == '.' && dots == 0:
			dots++
		case index == 0 && (character == '+' || character == '-'):
		default:
			return false
		}
	}

	return digits != 0
}

func parseDate(rule Rule, raw any, path string) (any, error) {
	var value time.Time
	switch raw := raw.(type) {
	case time.Time:
		value = raw
	case string:
		var parsed time.Time
		var err error
		if _, dateOnly := policy(rule, policyDateOnly); dateOnly {
			parsed, err = time.Parse(time.DateOnly, raw)
		} else {
			parsed, err = time.Parse(time.RFC3339, raw)
			if err != nil {
				parsed, err = time.Parse(time.DateOnly, raw)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("[%s] expected date in ISO format", path)
		}
		value = parsed
	default:
		return nil, fmt.Errorf("[%s] expected date but got %T", path, raw)
	}

	minimum, _ := parseDateBound(rule.MinDate)
	if !minimum.IsZero() && value.Before(minimum) {
		return nil, fmt.Errorf("[%s] expected date >= %s", path, rule.MinDate)
	}

	maximum, _ := parseDateBound(rule.MaxDate)
	if !maximum.IsZero() && value.After(maximum) {
		return nil, fmt.Errorf("[%s] expected date <= %s", path, rule.MaxDate)
	}

	return value, nil
}

func parseDateBound(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}

	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		parsed, err = time.Parse(time.DateOnly, value)
	}

	return parsed, err
}

func parseBytes(rule Rule, raw any, path string) (any, error) {
	if text, ok := raw.(string); ok {
		match := bytesPattern.FindStringSubmatch(strings.TrimSpace(text))
		if match == nil {
			return nil, fmt.Errorf("[%s] expected byte size like 64MB or 1.5GiB", path)
		}
		multipliers := map[string]int64{
			"":    1,
			"B":   1,
			"KB":  1e3,
			"MB":  1e6,
			"GB":  1e9,
			"TB":  1e12,
			"KIB": 1 << 10,
			"MIB": 1 << 20,
			"GIB": 1 << 30,
			"TIB": 1 << 40,
		}
		multiplier := multipliers[strings.ToUpper(match[2])]
		whole, err := strconv.ParseInt(match[1], 10, 64)
		if err == nil && whole <= math.MaxInt64/multiplier {
			raw = whole * multiplier
		} else {
			exact, ok := new(big.Rat).SetString(match[1])
			if !ok {
				return nil, fmt.Errorf("[%s] expected valid byte size", path)
			}
			exact.Mul(exact, new(big.Rat).SetInt64(multiplier))
			if !exact.IsInt() || !exact.Num().IsInt64() {
				return nil, fmt.Errorf("[%s] expected whole byte size in int64 range", path)
			}
			raw = exact.Num().Int64()
		}
	}
	value, err := parseInteger(rule, raw, path)
	if err != nil {
		return nil, err
	}

	if value.(int64) < 0 {
		return nil, fmt.Errorf("[%s] expected non-negative byte size", path)
	}

	return value, nil
}
func parsePath(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("[%s] expected non-empty path", path)
	}
	if _, required := policy(rule, policyLocalPath); required && !filepath.IsLocal(value) {
		return nil, fmt.Errorf("[%s] expected local path", path)
	}
	if _, required := policy(rule, policyCleanPath); required && filepath.Clean(value) != value {
		return nil, fmt.Errorf("[%s] expected clean path", path)
	}
	if extensions, configured := policy(rule, policyExtensions); configured {
		extension := filepath.Ext(value)
		matched := false
		for _, candidate := range extensions {
			if strings.EqualFold(extension, candidate) {
				matched = true

				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("[%s] expected path extension in [%s]", path, strings.Join(extensions, ", "))
		}
	}
	if patterns, configured := policy(rule, policyGlob); configured {
		matched, _ := filepath.Match(patterns[0], value)
		if !matched {
			return nil, fmt.Errorf("[%s] expected path matching %q", path, patterns[0])
		}
	}
	if roots, configured := policy(rule, policyWithin); configured {
		root, rootErr := filepath.Abs(roots[0])
		target, targetErr := filepath.Abs(value)
		if rootErr != nil || targetErr != nil {
			return nil, fmt.Errorf("[%s] cannot resolve path containment", path)
		}
		relative, relativeErr := filepath.Rel(root, target)
		if relativeErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("[%s] expected path within %s", path, roots[0])
		}
	}
	if rule.Absolute != nil && filepath.IsAbs(value) != *rule.Absolute {
		label := "relative"
		if *rule.Absolute {
			label = "absolute"
		}

		return nil, fmt.Errorf("[%s] expected %s path", path, label)
	}

	if _, required := policy(rule, policyNotExisting); required {
		if _, err := os.Lstat(value); err == nil || !os.IsNotExist(err) {
			return nil, fmt.Errorf("[%s] expected path not to exist", path)
		}
	}
	_, symlinkPolicy := policy(rule, policySymlink)
	_, executableRequired := policy(rule, policyExecutable)
	if !rule.Exists && !symlinkPolicy && !executableRequired {
		return value, nil
	}

	linkInfo, linkErr := os.Lstat(value)
	if symlinkPolicy {
		expected := rule.Policies[policySymlink][0] == "required"
		actual := linkErr == nil && linkInfo.Mode()&os.ModeSymlink != 0
		if actual != expected {
			return nil, fmt.Errorf("[%s] expected symlink %v", path, expected)
		}
	}
	if !rule.Exists && !executableRequired {
		return value, nil
	}
	info, err := os.Stat(value)
	if err != nil {
		return nil, fmt.Errorf("[%s] expected path to exist: %w", path, err)
	}

	if rule.PathKind == PathFile && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("[%s] expected path to be a file", path)
	}

	if rule.PathKind == PathDirectory && !info.IsDir() {
		return nil, fmt.Errorf("[%s] expected path to be a directory", path)
	}
	if executableRequired && info.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("[%s] expected executable path", path)
	}

	return value, nil
}

func parseBase64(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}

	if rule.Padding == PaddingRequired && len(value)%4 != 0 || rule.Padding == PaddingForbidden && strings.Contains(value, "=") {
		return nil, fmt.Errorf("[%s] expected valid base64 with %s padding", path, rule.Padding)
	}

	encoding := base64.StdEncoding
	rawEncoding := base64.RawStdEncoding
	if rule.URLSafe {
		encoding = base64.URLEncoding
		rawEncoding = base64.RawURLEncoding
	}

	var decodeErr error
	var decoded []byte
	if strings.Contains(value, "=") {
		decoded, decodeErr = encoding.DecodeString(value)
	} else {
		decoded, decodeErr = rawEncoding.DecodeString(value)
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("[%s] expected valid base64", path)
	}
	if minimum, configured := policyInt(rule, policyDecodedMin); configured && len(decoded) < minimum {
		return nil, fmt.Errorf("[%s] expected at least %d decoded bytes", path, minimum)
	}
	if maximum, configured := policyInt(rule, policyDecodedMax); configured && len(decoded) > maximum {
		return nil, fmt.Errorf("[%s] expected at most %d decoded bytes", path, maximum)
	}

	return value, nil
}

func parseEmail(raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value {
		return nil, fmt.Errorf("[%s] expected valid email", path)
	}

	return value, nil
}

func parsePort(rule Rule, raw any, path string) (any, error) {
	value, err := parseNumber(rule, raw, path, true)
	if err != nil {
		return nil, fmt.Errorf("[%s] expected valid port", path)
	}
	port := value.(int64)
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("[%s] expected valid port", path)
	}

	return port, nil
}

func parseURL(raw any, path string) (any, error) {
	return parseURLRule(Rule{}, raw, path)
}

func parseURLRule(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("[%s] expected valid URL", path)
	}

	if rule.Absolute != nil && !*rule.Absolute {
		if parsed.IsAbs() || strings.HasPrefix(value, "//") || value == "" {
			return nil, fmt.Errorf("[%s] expected relative URL", path)
		}
	} else if !parsed.IsAbs() || parsed.Hostname() == "" {
		if _, allowed := policy(rule, policyAllowRelative); !allowed {
			return nil, fmt.Errorf("[%s] expected valid URL", path)
		}
	}
	if len(rule.Schemes) != 0 || rule.URLCredentials != nil || rule.URLPort != nil || rule.URLQuery != nil || rule.URLFragment != nil || len(rule.Policies) != 0 {
		if len(rule.Schemes) != 0 {
			allowed := false
			for _, scheme := range rule.Schemes {
				if strings.EqualFold(parsed.Scheme, scheme) {
					allowed = true

					break
				}
			}
			if !allowed {
				return nil, fmt.Errorf("[%s] expected URL scheme in [%s]", path, strings.Join(rule.Schemes, ", "))
			}
		}
		checks := []struct {
			expected *bool
			actual   bool
			label    string
		}{
			{rule.URLCredentials, parsed.User != nil, "credentials"},
			{rule.URLPort, parsed.Port() != "", "port"},
			{rule.URLQuery, parsed.RawQuery != "" || parsed.ForceQuery, "query"},
			{rule.URLFragment, parsed.Fragment != "", "fragment"},
		}
		for _, check := range checks {
			if check.expected != nil && check.actual != *check.expected {
				verb := "without"
				if *check.expected {
					verb = "with"
				}

				return nil, fmt.Errorf("[%s] expected URL %s %s", path, verb, check.label)
			}
		}
		if err := validateURIPolicies(rule, parsed, path); err != nil {
			return nil, err
		}
		if _, canonical := policy(rule, policyCanonicalURI); canonical && !isCanonicalURI(parsed, value) {
			return nil, fmt.Errorf("[%s] expected canonical URI", path)
		}
	}

	return value, nil
}

func validateURIPolicies(rule Rule, parsed *url.URL, path string) error {
	if _, required := policy(rule, policyRequireHost); required && parsed.Hostname() == "" {
		return fmt.Errorf("[%s] expected URI with host", path)
	}
	if hosts, configured := policy(rule, policyURIHosts); configured {
		matched := false
		for _, host := range hosts {
			if strings.EqualFold(parsed.Hostname(), host) {
				matched = true

				break
			}
		}
		if !matched {
			return fmt.Errorf("[%s] expected URI host in [%s]", path, strings.Join(hosts, ", "))
		}
	}
	if suffixes, configured := policy(rule, policyHostSuffix); configured && !hasDomainSuffix(parsed.Hostname(), suffixes[0]) {
		return fmt.Errorf("[%s] expected URI host suffix %q", path, suffixes[0])
	}
	if expectation, configured := policy(rule, policyPathPresence); configured {
		present := parsed.EscapedPath() != ""
		if present != (expectation[0] == "required") {
			return fmt.Errorf("[%s] URI path presence did not match policy", path)
		}
	}
	if prefixes, configured := policy(rule, policyPathPrefix); configured && !strings.HasPrefix(parsed.EscapedPath(), prefixes[0]) {
		return fmt.Errorf("[%s] expected URI path prefix %q", path, prefixes[0])
	}
	if _, forbidden := policy(rule, policyOpaqueForbidden); forbidden && parsed.Opaque != "" {
		return fmt.Errorf("[%s] expected hierarchical URI", path)
	}
	if keys, configured := policy(rule, policyQueryKeys); configured {
		query := parsed.Query()
		for _, key := range keys {
			if _, exists := query[key]; !exists {
				return fmt.Errorf("[%s] expected URI query key %q", path, key)
			}
		}
	}
	if _, forbidden := policy(rule, policyUserPassword); forbidden && parsed.User != nil {
		if _, exists := parsed.User.Password(); exists {
			return fmt.Errorf("[%s] expected URI without user password", path)
		}
	}

	return nil
}

func isCanonicalURI(parsed *url.URL, value string) bool {
	if parsed.String() != value || parsed.Scheme != strings.ToLower(parsed.Scheme) || parsed.Hostname() != strings.ToLower(parsed.Hostname()) {
		return false
	}
	if parsed.Scheme == "http" && parsed.Port() == "80" || parsed.Scheme == "https" && parsed.Port() == "443" {
		return false
	}
	for segment := range strings.SplitSeq(parsed.EscapedPath(), "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}

	return true
}

func hasDomainSuffix(host string, suffix string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	suffix = strings.Trim(strings.ToLower(suffix), ".")

	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

func validURL(value string) bool {
	parsed, err := url.Parse(value)

	return err == nil && parsed.IsAbs() && parsed.Hostname() != ""
}
func parseHost(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	if _, allowed := policy(rule, policyAllowIPAddress); allowed {
		if _, err := netip.ParseAddr(value); err == nil {
			return value, nil
		}
	}
	hasTrailingDot := strings.HasSuffix(value, ".")
	if _, required := policy(rule, policyRequireTrailingDot); required && !hasTrailingDot {
		return nil, fmt.Errorf("[%s] expected hostname with trailing dot", path)
	}
	if hasTrailingDot {
		if _, allowed := policy(rule, policyAllowTrailingDot); !allowed {
			if _, required := policy(rule, policyRequireTrailingDot); !required {
				return nil, fmt.Errorf("[%s] expected hostname without trailing dot", path)
			}
		}
		value = strings.TrimSuffix(value, ".")
	}
	if !validHost(value) {
		return nil, fmt.Errorf("[%s] expected valid hostname", path)
	}
	labels := strings.Count(value, ".") + 1
	if minimum, configured := policyInt(rule, policyLabelsMin); configured && labels < minimum {
		return nil, fmt.Errorf("[%s] expected hostname with at least %d labels", path, minimum)
	}
	if maximum, configured := policyInt(rule, policyLabelsMax); configured && labels > maximum {
		return nil, fmt.Errorf("[%s] expected hostname with at most %d labels", path, maximum)
	}
	if suffixes, configured := policy(rule, policyHostSuffix); configured && !hasDomainSuffix(value, suffixes[0]) {
		return nil, fmt.Errorf("[%s] expected hostname suffix %q", path, suffixes[0])
	}
	if rule.Lowercase && strings.ToLower(value) != value {
		return nil, fmt.Errorf("[%s] expected lowercase hostname", path)
	}
	if rule.Uppercase && strings.ToUpper(value) != value {
		return nil, fmt.Errorf("[%s] expected uppercase hostname", path)
	}

	if hasTrailingDot {
		value += "."
	}

	return value, nil
}

func validHost(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}

	labelLength := 0
	for index := range len(value) {
		character := value[index]
		if character == '.' {
			if labelLength == 0 || value[index-1] == '-' {
				return false
			}
			labelLength = 0

			continue
		}
		if character >= 'A' && character <= 'Z' {
			character += 'a' - 'A'
		}
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '-' {
					return false
				}
			}
		}
		if labelLength == 0 && character == '-' {
			return false
		}
		labelLength++
		if labelLength > 63 {
			return false
		}
	}

	return labelLength != 0 && value[len(value)-1] != '-'
}

func parseUUID(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	if !uuidPattern.MatchString(value) {
		return nil, fmt.Errorf("[%s] expected valid UUIDv%s", path, rule.UUID)
	}
	version := UUIDVersion(value[14:15])
	if rule.UUID != "" && rule.UUID != UUIDAny && version != rule.UUID {
		return nil, fmt.Errorf("[%s] expected UUIDv%s", path, rule.UUID)
	}
	if versions, configured := policy(rule, policyUUIDVersions); configured {
		matched := slices.Contains(versions, string(version))
		if !matched {
			return nil, fmt.Errorf("[%s] expected allowed UUID version", path)
		}
	}
	lower := strings.ToLower(value)
	if _, required := policy(rule, policyNonNilUUID); required && lower == "00000000-0000-0000-0000-000000000000" {
		return nil, fmt.Errorf("[%s] expected non-nil UUID", path)
	}
	if _, required := policy(rule, policyNonMaxUUID); required && lower == "ffffffff-ffff-ffff-ffff-ffffffffffff" {
		return nil, fmt.Errorf("[%s] expected non-max UUID", path)
	}
	if _, required := policy(rule, policyRFCVariant); required && !strings.ContainsRune("89abAB", rune(value[19])) {
		return nil, fmt.Errorf("[%s] expected RFC 9562 UUID variant", path)
	}

	return value, nil
}

func parseIP(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	parsed, parseErr := netip.ParseAddr(value)
	if parseErr != nil || rule.IPVersion == IPv4 && !parsed.Is4() || rule.IPVersion == IPv6 && !parsed.Is6() {
		return nil, fmt.Errorf("[%s] expected valid IPv%s address", path, rule.IPVersion)
	}
	if classes, configured := policy(rule, policyIPClass); configured {
		for _, class := range classes {
			if !matchesIPClass(parsed, class) {
				return nil, fmt.Errorf("[%s] IP address violates %s policy", path, class)
			}
		}
	}

	return value, nil
}

func matchesIPClass(address netip.Addr, class string) bool {
	return class == "private" && address.IsPrivate() ||
		class == "public" && !address.IsPrivate() && !address.IsLoopback() && !address.IsUnspecified() && !address.IsMulticast() && !address.IsLinkLocalUnicast() ||
		class == "loopback" && address.IsLoopback() || class == "notLoopback" && !address.IsLoopback() ||
		class == "notUnspecified" && !address.IsUnspecified() || class == "multicast" && address.IsMulticast() ||
		class == "notMulticast" && !address.IsMulticast() || class == "linkLocal" && address.IsLinkLocalUnicast() ||
		class == "notLinkLocal" && !address.IsLinkLocalUnicast()
}

func parseHash(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	original := value
	if prefixes, configured := policy(rule, policyHashPrefix); configured {
		if !strings.HasPrefix(value, prefixes[0]) {
			return nil, fmt.Errorf("[%s] expected hash prefix %q", path, prefixes[0])
		}
		value = strings.TrimPrefix(value, prefixes[0])
	}
	parsed, err := parseHex(rule, value, path)
	if err != nil {
		return nil, err
	}
	lengths := map[HashAlgorithm]int{MD5: 32, SHA1: 40, SHA224: 56, SHA256: 64, SHA384: 96, SHA512: 128, SHA512_224: 56, SHA512_256: 64}
	if len(parsed.(string)) != lengths[rule.Hash] {
		return nil, fmt.Errorf("[%s] expected valid %s hash", path, rule.Hash)
	}

	return original, nil
}

func parseHex(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	if !hexPattern.MatchString(value) {
		return nil, fmt.Errorf("[%s] expected hexadecimal string", path)
	}
	if rule.Lowercase && strings.ToLower(value) != value {
		return nil, fmt.Errorf("[%s] expected lowercase hexadecimal string", path)
	}
	if rule.Uppercase && strings.ToUpper(value) != value {
		return nil, fmt.Errorf("[%s] expected uppercase hexadecimal string", path)
	}

	return value, nil
}

func parseSemanticVersion(value string) (semanticVersion, bool) {
	if !semVerPattern.MatchString(value) {
		return semanticVersion{}, false
	}
	core, _, _ := strings.Cut(value, "+")
	parts := strings.SplitN(core, "-", 2)
	numbers := strings.Split(parts[0], ".")
	major, _ := strconv.ParseUint(numbers[0], 10, 64)
	minor, _ := strconv.ParseUint(numbers[1], 10, 64)
	patch, _ := strconv.ParseUint(numbers[2], 10, 64)
	version := semanticVersion{major: major, minor: minor, patch: patch}
	if len(parts) == 2 {
		version.prerelease = strings.Split(parts[1], ".")
	}

	return version, true
}

func compareSemanticVersions(left semanticVersion, right semanticVersion) int {
	for _, pair := range [][2]uint64{{left.major, right.major}, {left.minor, right.minor}, {left.patch, right.patch}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	if len(left.prerelease) == 0 && len(right.prerelease) != 0 {
		return 1
	}
	if len(left.prerelease) != 0 && len(right.prerelease) == 0 {
		return -1
	}
	for index := 0; index < min(len(left.prerelease), len(right.prerelease)); index++ {
		leftNumber, leftErr := strconv.ParseUint(left.prerelease[index], 10, 64)
		rightNumber, rightErr := strconv.ParseUint(right.prerelease[index], 10, 64)
		if leftErr == nil && rightErr == nil && leftNumber != rightNumber {
			if leftNumber < rightNumber {
				return -1
			}

			return 1
		}
		if leftErr == nil && rightErr != nil {
			return -1
		}
		if leftErr != nil && rightErr == nil {
			return 1
		}
		if comparison := strings.Compare(left.prerelease[index], right.prerelease[index]); comparison != 0 {
			return comparison
		}
	}

	if len(left.prerelease) < len(right.prerelease) {
		return -1
	}
	if len(left.prerelease) > len(right.prerelease) {
		return 1
	}

	return 0
}

func semanticVersionBound(value string) semanticVersion {
	if cached, exists := parsedSemanticVersions.Load(value); exists {
		return cached.(semanticVersion)
	}
	parsed, _ := parseSemanticVersion(value)
	parsedSemanticVersions.Store(value, parsed)

	return parsed
}

func parseSemVer(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	parsed, valid := parseSemanticVersion(value)
	if !valid {
		return nil, fmt.Errorf("[%s] expected SemVer", path)
	}
	prerelease := len(parsed.prerelease) != 0
	build := strings.Contains(value, "+")
	if expected, configured := policy(rule, policySemVerPrerelease); configured && prerelease != (expected[0] == "required") {
		return nil, fmt.Errorf("[%s] semantic version prerelease policy failed", path)
	}
	if expected, configured := policy(rule, policySemVerBuild); configured && build != (expected[0] == "required") {
		return nil, fmt.Errorf("[%s] semantic version build metadata policy failed", path)
	}
	if minimum, configured := policy(rule, policySemVerMin); configured {
		bound := semanticVersionBound(minimum[0])
		if compareSemanticVersions(parsed, bound) < 0 {
			return nil, fmt.Errorf("[%s] expected semantic version >= %s", path, minimum[0])
		}
	}
	if maximum, configured := policy(rule, policySemVerMax); configured {
		bound := semanticVersionBound(maximum[0])
		if compareSemanticVersions(parsed, bound) >= 0 {
			return nil, fmt.Errorf("[%s] expected semantic version < %s", path, maximum[0])
		}
	}

	return value, nil
}

func parseTimeZone(raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	if _, err := time.LoadLocation(value); err != nil {
		return nil, fmt.Errorf("[%s] expected supported time zone", path)
	}

	return value, nil
}

func parseCIDR(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || rule.IPVersion == IPv4 && !prefix.Addr().Is4() || rule.IPVersion == IPv6 && !prefix.Addr().Is6() {
		return nil, fmt.Errorf("[%s] expected valid IPv%s CIDR", path, rule.IPVersion)
	}
	if _, required := policy(rule, policyCanonicalCIDR); required && prefix != prefix.Masked() {
		return nil, fmt.Errorf("[%s] expected canonical CIDR", path)
	}
	if bounds, configured := policy(rule, policyPrefixBounds); configured {
		minimum, _ := strconv.Atoi(bounds[0])
		maximum, _ := strconv.Atoi(bounds[1])
		if prefix.Bits() < minimum || prefix.Bits() > maximum {
			return nil, fmt.Errorf("[%s] expected CIDR prefix length between %d and %d", path, minimum, maximum)
		}
	}
	if addresses, configured := policy(rule, policyContainsAddresses); configured {
		for _, address := range addresses {
			parsed, parseErr := netip.ParseAddr(address)
			if parseErr != nil || !prefix.Contains(parsed) {
				return nil, fmt.Errorf("[%s] expected CIDR containing %s", path, address)
			}
		}
	}
	if parents, configured := policy(rule, policyContainedBy); configured {
		parent, parseErr := netip.ParsePrefix(parents[0])
		if parseErr != nil || !parent.Contains(prefix.Addr()) || parent.Bits() > prefix.Bits() {
			return nil, fmt.Errorf("[%s] expected CIDR contained by %s", path, parents[0])
		}
	}

	return prefix, nil
}

func parseEndpoint(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(value)
	_, allowEmpty := policy(rule, policyAllowEmptyHost)
	if err != nil || host == "" && !allowEmpty || port == "" {
		return nil, fmt.Errorf("[%s] expected host:port endpoint", path)
	}
	parsedPort, portErr := strconv.ParseUint(port, 10, 16)
	if portErr != nil {
		return nil, fmt.Errorf("[%s] expected endpoint with valid port", path)
	}
	if _, required := policy(rule, policyNonZeroPort); required && parsedPort == 0 {
		return nil, fmt.Errorf("[%s] expected endpoint with non-zero port", path)
	}
	if bounds, configured := policy(rule, policyPortBounds); configured {
		minimum, _ := strconv.ParseUint(bounds[0], 10, 16)
		maximum, _ := strconv.ParseUint(bounds[1], 10, 16)
		if parsedPort < minimum || parsedPort > maximum {
			return nil, fmt.Errorf("[%s] expected endpoint port between %d and %d", path, minimum, maximum)
		}
	}
	if host != "" {
		parsedIP, ipErr := netip.ParseAddr(host)
		if rule.IPVersion != "" && (ipErr != nil || rule.IPVersion == IPv4 && !parsedIP.Is4() || rule.IPVersion == IPv6 && !parsedIP.Is6()) {
			return nil, fmt.Errorf("[%s] expected endpoint with IPv%s host", path, rule.IPVersion)
		}
		if expectations, configured := policy(rule, policyEndpointHostType); configured {
			if expectations[0] == "ip" && ipErr != nil || expectations[0] == "hostname" && ipErr == nil {
				return nil, fmt.Errorf("[%s] endpoint host type did not match policy", path)
			}
		}
		if _, required := policy(rule, policyEndpointValidateHost); required && ipErr != nil && !validHost(host) {
			return nil, fmt.Errorf("[%s] expected endpoint with valid hostname", path)
		}
		if classes, configured := policy(rule, policyIPClass); configured {
			if ipErr != nil {
				return nil, fmt.Errorf("[%s] endpoint IP policy requires IP host", path)
			}
			for _, class := range classes {
				if !matchesIPClass(parsedIP, class) {
					return nil, fmt.Errorf("[%s] endpoint IP violates %s policy", path, class)
				}
			}
		}
	}

	return value, nil
}

func parseUnixSocket(rule Rule, raw any, path string) (any, error) {
	value, err := parsePath(rule, raw, path)
	if err != nil {
		return nil, err
	}
	if rule.Exists {
		info, _ := os.Stat(value.(string))
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("[%s] expected Unix socket", path)
		}
	}

	return value, nil
}

func parseTimestamp(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, fmt.Errorf("[%s] expected RFC3339 timestamp", path)
	}
	if rule.UTC && parsed.Location() != time.UTC {
		return nil, fmt.Errorf("[%s] expected UTC timestamp", path)
	}
	if _, required := policy(rule, policyRequireOffset); required && strings.HasSuffix(strings.ToUpper(value), "Z") {
		return nil, fmt.Errorf("[%s] expected explicit numeric timestamp offset", path)
	}
	fractional := strings.Contains(strings.SplitN(value, "T", 2)[1], ".")
	if expected, configured := policy(rule, policyFractionalSeconds); configured && fractional != (expected[0] == "required") {
		return nil, fmt.Errorf("[%s] timestamp fractional-second policy failed", path)
	}
	if values, configured := policy(rule, policyTimePrecision); configured {
		precision, parseErr := time.ParseDuration(values[0])
		if parseErr != nil || precision <= 0 || parsed.Nanosecond()%int(precision) != 0 {
			return nil, fmt.Errorf("[%s] timestamp does not match precision %s", path, values[0])
		}
	}
	minimum, _ := parseDateBound(rule.MinDate)
	if !minimum.IsZero() && parsed.Before(minimum) {
		return nil, fmt.Errorf("[%s] expected timestamp >= %s", path, rule.MinDate)
	}
	maximum, _ := parseDateBound(rule.MaxDate)
	if !maximum.IsZero() && parsed.After(maximum) {
		return nil, fmt.Errorf("[%s] expected timestamp <= %s", path, rule.MaxDate)
	}

	return parsed, nil
}

func parseTimeOfDay(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	layouts := []string{"15:04", "15:04:05"}
	if _, configured := policy(rule, policyFractionalSeconds); configured {
		layouts = append(layouts, "15:04:05.999999999")
	}
	for _, layout := range layouts {
		if _, err := time.Parse(layout, value); err == nil {
			if _, required := policy(rule, policyTimeSeconds); required && len(value) < len("15:04:05") {
				break
			}
			fractional := strings.Contains(value, ".")
			if expected, configured := policy(rule, policyFractionalSeconds); configured && fractional != (expected[0] == "required") {
				break
			}

			return value, nil
		}
	}

	return nil, fmt.Errorf("[%s] expected time of day as HH:MM or HH:MM:SS", path)
}

func parseMap(rule Rule, raw any, path string) (any, error) {
	var entries []string
	if value, ok := raw.(string); ok {
		if _, configured := policy(rule, policyCSV); configured {
			records, err := csv.NewReader(strings.NewReader(value)).ReadAll()
			if err != nil || len(records) != 1 {
				return nil, fmt.Errorf("[%s] expected one CSV record", path)
			}
			entries = records[0]
		} else {
			entries = strings.Split(value, rule.Separator)
		}
	} else if values, ok := raw.(map[string]any); ok {
		if err := checkItemCount(rule, len(values), path); err != nil {
			return nil, err
		}
		parsed := make(map[string]any, len(values))
		for keyRaw, valueRaw := range values {
			if _, required := policy(rule, policyRejectEmptyKeys); required && keyRaw == "" {
				return nil, fmt.Errorf("[%s] expected non-empty map key", path)
			}
			if _, required := policy(rule, policyRejectEmptyValues); required {
				if valueString, stringValue := valueRaw.(string); stringValue && valueString == "" {
					return nil, fmt.Errorf("[%s] expected non-empty map value for %q", path, keyRaw)
				}
			}
			key, err := parseRule(*rule.Key, keyRaw, path+"{key}")
			if err != nil {
				return nil, err
			}
			keyString := key.(string)
			if _, exists := parsed[keyString]; exists {
				return nil, fmt.Errorf("[%s] duplicate map key %q", path, keyString)
			}
			value, err := parseRule(*rule.Item, valueRaw, path+"["+keyRaw+"]")
			if err != nil {
				return nil, err
			}
			parsed[keyString] = value
		}

		return parsed, nil
	} else {
		return nil, fmt.Errorf("[%s] expected delimited map but got %T", path, raw)
	}

	if err := checkItemCount(rule, len(entries), path); err != nil {
		return nil, err
	}
	parsed := make(map[string]any, len(entries))
	for index, entry := range entries {
		parts := strings.SplitN(entry, rule.KeyValueSeparator, 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("[%s] item %d has no key/value separator", path, index)
		}
		keyRaw, valueRaw := parts[0], parts[1]
		if rule.ListTrim {
			keyRaw, valueRaw = strings.TrimSpace(keyRaw), strings.TrimSpace(valueRaw)
		}
		if _, required := policy(rule, policyRejectEmptyKeys); required && keyRaw == "" {
			return nil, fmt.Errorf("[%s] expected non-empty map key", path)
		}
		if _, required := policy(rule, policyRejectEmptyValues); required && valueRaw == "" {
			return nil, fmt.Errorf("[%s] expected non-empty map value for %q", path, keyRaw)
		}

		key, err := parseRule(*rule.Key, keyRaw, path+"{key}")
		if err != nil {
			return nil, err
		}
		keyString := key.(string)
		if _, exists := parsed[keyString]; exists {
			return nil, fmt.Errorf("[%s] duplicate map key %q", path, keyString)
		}
		parsedValue, err := parseRule(*rule.Item, valueRaw, path+"["+keyString+"]")
		if err != nil {
			return nil, err
		}
		parsed[keyString] = parsedValue
	}

	return parsed, nil
}

func parseRegexp(raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	compiled, err := regexp.Compile(value)
	if err != nil {
		return nil, fmt.Errorf("[%s] expected valid regular expression: %w", path, err)
	}

	return compiled, nil
}

func validatePEMPolicies(rule Rule, block *pem.Block, path string) error {
	if blockTypes, configured := policy(rule, policyPEMBlockTypes); configured {
		matched := slices.Contains(blockTypes, block.Type)
		if !matched {
			return fmt.Errorf("[%s] expected PEM block type in [%s]", path, strings.Join(blockTypes, ", "))
		}
	}
	if headers, configured := policy(rule, policyPEMHeaders); configured && headers[0] == "forbidden" && len(block.Headers) != 0 {
		return fmt.Errorf("[%s] expected PEM block without headers", path)
	}

	return nil
}

func validateCertificatePolicies(rule Rule, certificate *x509.Certificate, path string) error {
	if err := validateKeyPolicies(rule, certificate.PublicKey, path); err != nil {
		return err
	}

	if values, configured := policy(rule, policyValidAt); configured {
		moment := time.Now()
		if values[0] != "now" {
			parsed, err := time.Parse(time.RFC3339Nano, values[0])
			if err != nil {
				return fmt.Errorf("[%s] certificate has invalid validation time", path)
			}
			moment = parsed
		}
		if moment.Before(certificate.NotBefore) || moment.After(certificate.NotAfter) {
			return fmt.Errorf("[%s] certificate is not valid at %s", path, moment.Format(time.RFC3339Nano))
		}
	}
	if values, configured := policy(rule, policyValidFor); configured {
		duration, err := time.ParseDuration(values[0])
		if err != nil || time.Until(certificate.NotAfter) < duration {
			return fmt.Errorf("[%s] certificate validity is shorter than %s", path, values[0])
		}
	}
	if hostnames, configured := policy(rule, policyCertificateHostname); configured {
		if err := certificate.VerifyHostname(hostnames[0]); err != nil {
			return fmt.Errorf("[%s] certificate is not valid for %s: %w", path, hostnames[0], err)
		}
	}
	if expectations, configured := policy(rule, policyCACertificate); configured && certificate.IsCA != (expectations[0] == "required") {
		return fmt.Errorf("[%s] certificate CA policy failed", path)
	}
	if usages, configured := policy(rule, policyCertificateUsage); configured {
		for _, requested := range usages {
			expected := x509.ExtKeyUsageServerAuth
			if requested == "client" {
				expected = x509.ExtKeyUsageClientAuth
			}
			matched := false
			for _, actual := range certificate.ExtKeyUsage {
				if actual == expected || actual == x509.ExtKeyUsageAny {
					matched = true

					break
				}
			}
			if !matched {
				return fmt.Errorf("[%s] certificate lacks %s authentication usage", path, requested)
			}
		}
	}

	return nil
}

func keyAlgorithm(key any) string {
	switch key.(type) {
	case *rsa.PrivateKey, *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		return "ECDSA"
	case ed25519.PrivateKey, ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", key)
	}
}

func validateKeyPolicies(rule Rule, key any, path string) error {
	if algorithms, configured := policy(rule, policyPrivateKeyAlgorithms); configured {
		actual := keyAlgorithm(key)
		matched := false
		for _, algorithm := range algorithms {
			if strings.EqualFold(actual, algorithm) {
				matched = true

				break
			}
		}

		if !matched {
			return fmt.Errorf("[%s] expected key algorithm in [%s]", path, strings.Join(algorithms, ", "))
		}
	}

	if minimum, configured := policyInt(rule, policyMinRSA); configured {
		var bits int
		switch key := key.(type) {
		case *rsa.PrivateKey:
			bits = key.N.BitLen()
		case *rsa.PublicKey:
			bits = key.N.BitLen()
		default:
			return fmt.Errorf("[%s] RSA bit constraint requires RSA key", path)
		}

		if bits < minimum {
			return fmt.Errorf("[%s] expected RSA key with at least %d bits", path, minimum)
		}
	}

	return nil
}

func parsePEM(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode([]byte(value))
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("[%s] expected one PEM block", path)
	}
	if err := validatePEMPolicies(rule, block, path); err != nil {
		return nil, err
	}

	return []byte(value), nil
}

func parseCertificate(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}

	block, rest := pem.Decode([]byte(value))
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("[%s] expected one PEM certificate", path)
	}

	if err := validatePEMPolicies(rule, block, path); err != nil {
		return nil, err
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("[%s] expected X.509 certificate: %w", path, err)
	}
	if err := validateCertificatePolicies(rule, certificate, path); err != nil {
		return nil, err
	}

	return certificate, nil
}

func parsePrivateKey(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}

	block, rest := pem.Decode([]byte(value))
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("[%s] expected one PEM private key", path)
	}

	if err := validatePEMPolicies(rule, block, path); err != nil {
		return nil, err
	}

	pkcs8Key, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
	pkcs1Key, pkcs1Err := x509.ParsePKCS1PrivateKey(block.Bytes)
	ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes)
	if pkcs8Err != nil && pkcs1Err != nil && ecErr != nil {
		return nil, fmt.Errorf("[%s] expected supported private key", path)
	}

	var key any
	switch {
	case pkcs8Err == nil:
		key = pkcs8Key
	case pkcs1Err == nil:
		key = pkcs1Key
	default:
		key = ecKey
	}

	if _, required := policy(rule, policyPKCS8); required && pkcs8Err != nil {
		return nil, fmt.Errorf("[%s] expected PKCS#8 private key", path)
	}
	if err := validateKeyPolicies(rule, key, path); err != nil {
		return nil, err
	}

	return SecretValue{value: value}, nil
}

func parseURI(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(value)
	_, allowRelative := policy(rule, policyAllowRelative)
	if err != nil || parsed.Scheme == "" && !allowRelative || strings.ContainsAny(value, "\r\n\t ") {
		return nil, fmt.Errorf("[%s] expected absolute URI", path)
	}
	if err := validateURIPolicies(rule, parsed, path); err != nil {
		return nil, err
	}
	if _, canonical := policy(rule, policyCanonicalURI); canonical && !isCanonicalURI(parsed, value) {
		return nil, fmt.Errorf("[%s] expected canonical URI", path)
	}

	return value, nil
}

func parseMACAddress(raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	address, err := net.ParseMAC(value)
	if err != nil {
		return nil, fmt.Errorf("[%s] expected MAC address", path)
	}

	return address, nil
}

func parsePublicKey(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode([]byte(value))
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("[%s] expected one PEM public key", path)
	}
	if err := validatePEMPolicies(rule, block, path); err != nil {
		return nil, err
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	}
	if err != nil {
		certificate, certificateErr := x509.ParseCertificate(block.Bytes)
		if certificateErr != nil {
			return nil, fmt.Errorf("[%s] expected supported public key", path)
		}
		key = certificate.PublicKey
	}
	if err := validateKeyPolicies(rule, key, path); err != nil {
		return nil, err
	}

	return PublicKeyValue{key: key}, nil
}

func parseCertificateBundle(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	remaining := []byte(value)
	certificates := make([]*x509.Certificate, 0, 1)
	for len(strings.TrimSpace(string(remaining))) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, fmt.Errorf("[%s] expected PEM certificate bundle", path)
		}
		if err := validatePEMPolicies(rule, block, path); err != nil {
			return nil, err
		}
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("[%s] expected X.509 certificate: %w", path, parseErr)
		}
		if err := validateCertificatePolicies(rule, certificate, path); err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
		remaining = rest
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("[%s] expected at least one certificate", path)
	}

	return certificates, nil
}

func parseBigInt(rule Rule, raw any, path string) (any, error) {
	if value, ok := raw.(big.Int); ok {
		return validateBigInt(rule, value, path)
	}
	var value string
	switch raw := raw.(type) {
	case json.Number:
		exact, ok := new(big.Rat).SetString(raw.String())
		if !ok || !exact.IsInt() {
			return nil, fmt.Errorf("[%s] expected arbitrary-precision integer", path)
		}

		return validateBigInt(rule, *exact.Num(), path)
	case string:
		value = raw
	case int:
		return validateBigInt(rule, *big.NewInt(int64(raw)), path)
	case int64:
		return validateBigInt(rule, *big.NewInt(raw), path)
	case uint64:
		return validateBigInt(rule, *new(big.Int).SetUint64(raw), path)
	default:
		return nil, fmt.Errorf("[%s] expected arbitrary-precision integer", path)
	}
	base := 10
	if configured, exists := policyInt(rule, policyBase); exists {
		base = configured
	}
	parsed, ok := new(big.Int).SetString(strings.TrimSpace(value), base)
	if !ok {
		return nil, fmt.Errorf("[%s] expected arbitrary-precision integer", path)
	}

	return validateBigInt(rule, *parsed, path)
}

func validateBigInt(rule Rule, value big.Int, path string) (any, error) {
	if rule.Positive && value.Sign() <= 0 || rule.Negative && value.Sign() >= 0 || rule.RejectZero && value.Sign() == 0 {
		return nil, fmt.Errorf("[%s] arbitrary-precision integer violates sign policy", path)
	}
	if err := validateExactNumberBounds(rule, new(big.Rat).SetInt(&value), path, "arbitrary-precision integer"); err != nil {
		return nil, err
	}

	return value, nil
}

func parseDecimal(rule Rule, raw any, path string) (any, error) {
	if value, ok := raw.(big.Rat); ok {
		return validateDecimal(rule, value, path)
	}
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(value)
	if strings.Contains(trimmed, "/") {
		return nil, fmt.Errorf("[%s] expected exact decimal", path)
	}
	parsed, ok := new(big.Rat).SetString(trimmed)
	if !ok {
		return nil, fmt.Errorf("[%s] expected exact decimal", path)
	}

	return validateDecimal(rule, *parsed, path)
}

func validateDecimal(rule Rule, value big.Rat, path string) (any, error) {
	if rule.Positive && value.Sign() <= 0 || rule.Negative && value.Sign() >= 0 || rule.RejectZero && value.Sign() == 0 {
		return nil, fmt.Errorf("[%s] exact decimal violates sign policy", path)
	}
	if err := validateExactNumberBounds(rule, &value, path, "exact decimal"); err != nil {
		return nil, err
	}

	return value, nil
}

func validateExactNumberBounds(rule Rule, value *big.Rat, path string, description string) error {
	checks := []struct {
		bound     *float64
		exclusive bool
		minimum   bool
	}{
		{rule.Min, false, true},
		{rule.ExclusiveMin, true, true},
		{rule.Max, false, false},
		{rule.ExclusiveMax, true, false},
	}
	for _, check := range checks {
		if check.bound == nil {
			continue
		}
		bound, ok := new(big.Rat).SetString(strconv.FormatFloat(*check.bound, 'g', -1, 64))
		if !ok {
			return fmt.Errorf("[%s] expected finite numeric bound", path)
		}
		comparison := value.Cmp(bound)
		if check.minimum && (comparison < 0 || check.exclusive && comparison == 0) {
			return fmt.Errorf("[%s] %s is below minimum", path, description)
		}
		if !check.minimum && (comparison > 0 || check.exclusive && comparison == 0) {
			return fmt.Errorf("[%s] %s is above maximum", path, description)
		}
	}
	if rule.Multiple != nil {
		multiple, ok := new(big.Rat).SetString(strconv.FormatFloat(*rule.Multiple, 'g', -1, 64))
		if !ok || multiple.Sign() <= 0 {
			return fmt.Errorf("[%s] multiple must be finite and positive", path)
		}
		quotient := new(big.Rat).Quo(value, multiple)
		if !quotient.IsInt() {
			return fmt.Errorf("[%s] %s must be a multiple of %v", path, description, *rule.Multiple)
		}
	}

	return nil
}

func parseMediaType(rule Rule, raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	_, parameters, err := mime.ParseMediaType(value)
	if err != nil {
		return nil, fmt.Errorf("[%s] expected media type", path)
	}
	if expectation, configured := policy(rule, policyMediaParameters); configured {
		required := expectation[0] == "required"
		if required != (len(parameters) != 0) {
			return nil, fmt.Errorf("[%s] media type parameter policy failed", path)
		}
	}

	return value, nil
}

func parseFileMode(raw any, path string) (any, error) {
	if value, ok := raw.(fs.FileMode); ok {
		return value, nil
	}
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 8, 12)
	if err != nil || parsed > 0o7777 {
		return nil, fmt.Errorf("[%s] expected octal file mode", path)
	}
	mode := fs.FileMode(parsed & 0o777)
	if parsed&0o4000 != 0 {
		mode |= fs.ModeSetuid
	}
	if parsed&0o2000 != 0 {
		mode |= fs.ModeSetgid
	}
	if parsed&0o1000 != 0 {
		mode |= fs.ModeSticky
	}

	return mode, nil
}

func parseULID(raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	if !ulidPattern.MatchString(value) {
		return nil, fmt.Errorf("[%s] expected canonical ULID", path)
	}

	return strings.ToUpper(value), nil
}

func parseGlob(raw any, path string) (any, error) {
	value, err := requireString(raw, path)
	if err != nil {
		return nil, err
	}
	if _, err := filepath.Match(value, ""); err != nil {
		return nil, fmt.Errorf("[%s] expected valid filesystem glob: %w", path, err)
	}

	return value, nil
}

// Load reads and parses a schema from the process environment and dotenv files.
func Load(schema Schema) (Values, error) {
	lookup, err := LookupEnvFiles()
	if err != nil {
		return nil, err
	}

	return LoadFrom(schema, lookup)
}

// LoadFrom reads and parses a schema with an explicit lookup function.
func LoadFrom(schema Schema, lookup LookupFunc) (Values, error) {
	if !schema.validated {
		if err := schema.Validate(); err != nil {
			return nil, err
		}
		schema.validated = true
	}
	values := make(Values, len(schema.Variables))
	if err := validateConstraints(schema, lookup, values); err != nil {
		return nil, err
	}

	for _, variable := range schema.Variables {
		if _, parsed := values[variable.Name]; parsed {
			continue
		}
		value, present, err := parseVariable(variable.Rule, variable.Name, variable.Fallbacks, lookup)
		if err != nil {
			return nil, err
		}
		if !present {
			continue
		}
		values[variable.Name] = value
	}

	return values, nil
}

// ValidateConstraints evaluates a schema's cross-variable constraints.
func ValidateConstraints(schema Schema, lookup LookupFunc) error {
	return validateConstraints(schema, lookup, nil)
}

func validateConstraints(schema Schema, lookup LookupFunc, parsed Values) error {
	if len(schema.Constraints) == 0 {
		return nil
	}
	var indexed map[string]*Variable
	if len(schema.Variables) > 16 {
		indexed = make(map[string]*Variable, len(schema.Variables))
		for index := range schema.Variables {
			variable := &schema.Variables[index]
			indexed[variable.Name] = variable
		}
	}
	variableFor := func(name string) *Variable {
		if indexed != nil {
			return indexed[name]
		}
		for index := range schema.Variables {
			if schema.Variables[index].Name == name {
				return &schema.Variables[index]
			}
		}

		return nil
	}
	read := func(name string) (string, bool) {
		variable := variableFor(name)
		if variable == nil {
			return "", false
		}
		value, exists := lookup(name)
		for index := 0; !exists && index < len(variable.Fallbacks); index++ {
			value, exists = lookup(variable.Fallbacks[index])
		}

		if (!exists || value == "" && !variable.Rule.EmptyAllowed) && variable.Rule.HasDefault {
			return fmt.Sprint(variable.Rule.Default), true
		}

		return value, exists && (value != "" || variable.Rule.EmptyAllowed)
	}
	parsedValue := func(name string) (any, bool, error) {
		if value, exists := parsed[name]; exists {
			return value, true, nil
		}
		variable := variableFor(name)
		if variable == nil {
			return nil, false, fmt.Errorf("unknown variable %q", name)
		}
		value, present, err := parseVariable(variable.Rule, variable.Name, variable.Fallbacks, lookup)
		if err == nil && present && parsed != nil {
			parsed[name] = value
		}

		return value, present, err
	}
	conditionMatches := func(name string, expected string) (bool, error) {
		value, present, err := parsedValue(name)
		if err != nil || !present {
			return false, err
		}

		rule := variableFor(name).Rule
		expectedValue, err := parseRule(rule, expected, name+" constraint")
		if err != nil {
			return false, err
		}

		return reflect.DeepEqual(value, expectedValue), nil
	}
	for _, constraint := range schema.Constraints {
		present := 0
		for _, name := range constraint.Names {
			if _, exists := read(name); exists {
				present++
			}
		}
		switch constraint.Kind {
		case ConstraintExactlyOne:
			if present != 1 {
				return fmt.Errorf("envschema: exactly one of [%s] must be defined", strings.Join(constraint.Names, ", "))
			}
		case ConstraintAtLeastOne:
			if present == 0 {
				return fmt.Errorf("envschema: at least one of [%s] must be defined", strings.Join(constraint.Names, ", "))
			}
		case ConstraintMutuallyExclusive:
			if present > 1 {
				return fmt.Errorf("envschema: variables [%s] are mutually exclusive", strings.Join(constraint.Names, ", "))
			}
		case ConstraintRequiredTogether:
			if present != 0 && present != len(constraint.Names) {
				return fmt.Errorf("envschema: variables [%s] must be defined together", strings.Join(constraint.Names, ", "))
			}
		case ConstraintRequiredWhen:
			matches, err := conditionMatches(constraint.Names[0], constraint.Value)
			if err != nil {
				return err
			}
			if matches {
				for _, name := range constraint.Names[1:] {
					if _, requiredExists := read(name); !requiredExists {
						return fmt.Errorf("envschema: %s is required when %s=%q", name, constraint.Names[0], constraint.Value)
					}
				}
			}
		case ConstraintForbiddenWhen:
			matches, err := conditionMatches(constraint.Names[0], constraint.Value)
			if err != nil {
				return err
			}
			if matches {
				for _, name := range constraint.Names[1:] {
					if _, forbiddenExists := read(name); forbiddenExists {
						return fmt.Errorf("envschema: %s is forbidden when %s=%q", name, constraint.Names[0], constraint.Value)
					}
				}
			}
		case ConstraintRequiredUnless:
			matches, err := conditionMatches(constraint.Names[0], constraint.Value)
			if err != nil {
				return err
			}
			if !matches {
				for _, name := range constraint.Names[1:] {
					if _, requiredExists := read(name); !requiredExists {
						return fmt.Errorf("envschema: %s is required unless %s=%q", name, constraint.Names[0], constraint.Value)
					}
				}
			}
		case ConstraintRequiredIfPresent:
			if _, exists := read(constraint.Names[0]); exists {
				for _, name := range constraint.Names[1:] {
					if _, requiredExists := read(name); !requiredExists {
						return fmt.Errorf("envschema: %s is required when %s is present", name, constraint.Names[0])
					}
				}
			}
		case ConstraintEqualValues, ConstraintDifferentValues, ConstraintLessThanVariable:
			left, leftPresent, leftErr := parsedValue(constraint.Names[0])
			right, rightPresent, rightErr := parsedValue(constraint.Names[1])
			if leftErr != nil {
				return leftErr
			}
			if rightErr != nil {
				return rightErr
			}
			if !leftPresent || !rightPresent {
				continue
			}
			if constraint.Kind == ConstraintEqualValues && !reflect.DeepEqual(left, right) {
				return fmt.Errorf("envschema: variables [%s] must be equal", strings.Join(constraint.Names, ", "))
			}
			if constraint.Kind == ConstraintDifferentValues && reflect.DeepEqual(left, right) {
				return fmt.Errorf("envschema: variables [%s] must differ", strings.Join(constraint.Names, ", "))
			}
			if constraint.Kind == ConstraintLessThanVariable {
				comparison, comparable := compareConstraintValues(left, right)
				if !comparable || comparison >= 0 {
					return fmt.Errorf("envschema: %s must be less than %s", constraint.Names[0], constraint.Names[1])
				}
			}
		case ConstraintTLSKeyPair:
			certificateValue, certificateExists := read(constraint.Names[0])
			privateKeyValue, privateKeyExists := read(constraint.Names[1])
			if !certificateExists || !privateKeyExists {
				return fmt.Errorf("envschema: TLS key pair variables [%s] must both be defined", strings.Join(constraint.Names, ", "))
			}
			if err := validateTLSKeyPair(certificateValue, privateKeyValue); err != nil {
				return fmt.Errorf("envschema: TLS key pair [%s]: %w", strings.Join(constraint.Names, ", "), err)
			}
		}
	}

	return nil
}

func constraintRat(value any) (*big.Rat, bool) {
	switch value := value.(type) {
	case int64:
		return new(big.Rat).SetInt64(value), true
	case uint64:
		return new(big.Rat).SetUint64(value), true
	case float64:
		return new(big.Rat).SetFloat64(value), true
	case time.Duration:
		return new(big.Rat).SetInt64(int64(value)), true
	case big.Int:
		return new(big.Rat).SetInt(&value), true
	case big.Rat:
		return new(big.Rat).Set(&value), true
	default:
		return nil, false
	}
}

func compareConstraintValues(left any, right any) (int, bool) {
	if leftTime, ok := left.(time.Time); ok {
		rightTime, rightOK := right.(time.Time)
		if !rightOK {
			return 0, false
		}
		if leftTime.Before(rightTime) {
			return -1, true
		}
		if leftTime.After(rightTime) {
			return 1, true
		}

		return 0, true
	}
	switch left := left.(type) {
	case big.Int:
		switch right := right.(type) {
		case big.Int:
			return left.Cmp(&right), true
		case big.Rat:
			var scaled big.Int
			scaled.Mul(&left, right.Denom())

			return scaled.Cmp(right.Num()), true
		}
	case big.Rat:
		switch right := right.(type) {
		case big.Int:
			var scaled big.Int
			scaled.Mul(&right, left.Denom())

			return left.Num().Cmp(&scaled), true
		case big.Rat:
			return left.Cmp(&right), true
		}
	}
	leftRat, leftOK := constraintRat(left)
	rightRat, rightOK := constraintRat(right)
	if !leftOK || !rightOK {
		return 0, false
	}

	return leftRat.Cmp(rightRat), true
}

func parsePrivateKeyMaterial(value string) (any, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("invalid private key PEM")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("unsupported private key")
}

func validateTLSKeyPair(certificatePEM string, privateKeyPEM string) error {
	block, rest := pem.Decode([]byte(certificatePEM))
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return fmt.Errorf("invalid certificate PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("invalid certificate: %w", err)
	}
	privateKey, err := parsePrivateKeyMaterial(privateKeyPEM)
	if err != nil {
		return err
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("private key cannot produce a public key")
	}
	certificatePublic, certificateErr := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	privatePublic, privateErr := x509.MarshalPKIXPublicKey(signer.Public())
	if certificateErr != nil || privateErr != nil || !reflect.DeepEqual(certificatePublic, privatePublic) {
		return fmt.Errorf("certificate and private key do not match")
	}

	return nil
}

// Release returns the sensitive source text.
func (secret SecretValue) Release() string {
	return secret.value
}

// Key returns the parsed public-key value.
func (value PublicKeyValue) Key() any {
	return value.key
}

// String returns the redaction marker.
func (secret SecretValue) String() string {
	return redactedSecret
}

// GoString returns the redaction marker for Go-syntax formatting.
func (secret SecretValue) GoString() string {
	return redactedSecret
}

// Format writes the redaction marker for every formatting verb.
func (secret SecretValue) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(redactedSecret))
}

// MarshalJSON returns a JSON string containing the redaction marker.
func (secret SecretValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(redactedSecret)
}

// MarshalText returns the redaction marker.
func (secret SecretValue) MarshalText() ([]byte, error) {
	return []byte(redactedSecret), nil
}

// Value returns a parsed value by its primary environment name.
func (values Values) Value(name string) (any, bool) {
	value, ok := values[name]

	return value, ok
}

// ValueAs returns a parsed value converted to T where supported.
func ValueAs[T any](values Values, name string) (T, error) {
	var result T
	value, ok := values[name]
	if !ok {
		return result, fmt.Errorf("environment variable %q has no value", name)
	}
	if typed, ok := value.(T); ok {
		return typed, nil
	}

	target := reflect.ValueOf(&result).Elem()
	if err := assignValue(target, reflect.ValueOf(value)); err != nil {
		return result, fmt.Errorf("environment variable %q: %w", name, err)
	}

	return result, nil
}

// Read parses one named value as T.
func Read[T any](rule Rule, name string, lookup LookupFunc) (T, bool, error) {
	return ReadWithFallbacks[T](rule, name, nil, lookup)
}

// ReadWithFallbacks parses one named value as T, consulting fallbacks in order.
func ReadWithFallbacks[T any](rule Rule, name string, fallbacks []string, lookup LookupFunc) (T, bool, error) {
	var result T
	value, present, err := parseVariable(rule, name, fallbacks, lookup)
	if err != nil || !present {
		return result, present, err
	}
	if typed, ok := value.(T); ok {
		return typed, true, nil
	}

	target := reflect.ValueOf(&result).Elem()
	if err := assignValue(target, reflect.ValueOf(value)); err != nil {
		return result, false, fmt.Errorf("environment variable %q: %w", name, err)
	}

	return result, true, nil
}

// ReadText parses one custom value through encoding.TextUnmarshaler.
func ReadText[T any](rule Rule, name string, lookup LookupFunc) (T, bool, error) {
	return ReadTextWithFallbacks[T](rule, name, nil, lookup)
}

// ReadTextWithFallbacks parses one custom value after consulting fallbacks.
func ReadTextWithFallbacks[T any](rule Rule, name string, fallbacks []string, lookup LookupFunc) (T, bool, error) {
	var result T
	value, present, err := parseVariable(rule, name, fallbacks, lookup)
	if err != nil || !present {
		return result, present, err
	}
	unmarshaler, ok := any(&result).(encoding.TextUnmarshaler)
	if !ok {
		return result, false, fmt.Errorf("environment variable %q: %T does not implement encoding.TextUnmarshaler", name, &result)
	}
	if err := unmarshaler.UnmarshalText([]byte(value.(string))); err != nil {
		return result, false, fmt.Errorf("environment variable %q: %w", name, err)
	}

	return result, true, nil
}

// LookupEnv reads one name from the process environment.
func LookupEnv(name string) (string, bool) {
	return lookupOS(name)
}

func assignValue(target reflect.Value, source reflect.Value) error {
	if !source.IsValid() {
		return fmt.Errorf("cannot assign a nil value to %s", target.Type())
	}

	for source.Kind() == reflect.Interface {
		if source.IsNil() {
			return fmt.Errorf("cannot assign a nil value to %s", target.Type())
		}
		source = source.Elem()
	}

	if source.Type().AssignableTo(target.Type()) {
		target.Set(source)

		return nil
	}

	if target.Kind() == reflect.Slice && source.Kind() == reflect.Slice {
		converted := reflect.MakeSlice(target.Type(), source.Len(), source.Len())
		for index := 0; index < source.Len(); index++ {
			if err := assignValue(converted.Index(index), source.Index(index)); err != nil {
				return fmt.Errorf("item %d: %w", index, err)
			}
		}
		target.Set(converted)

		return nil
	}
	if target.Kind() == reflect.Map && source.Kind() == reflect.Map {
		converted := reflect.MakeMapWithSize(target.Type(), source.Len())
		iterator := source.MapRange()
		for iterator.Next() {
			key := reflect.New(target.Type().Key()).Elem()
			if err := assignValue(key, iterator.Key()); err != nil {
				return fmt.Errorf("map key: %w", err)
			}
			value := reflect.New(target.Type().Elem()).Elem()
			if err := assignValue(value, iterator.Value()); err != nil {
				return fmt.Errorf("map value: %w", err)
			}
			converted.SetMapIndex(key, value)
		}
		target.Set(converted)

		return nil
	}

	return fmt.Errorf("cannot assign %s to %s", source.Type(), target.Type())
}

// DecodeJSON decodes a validated JSON value into T.
func DecodeJSON[T any](raw json.RawMessage) (T, error) {
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		return value, err
	}

	return value, nil
}

var _ fmt.Stringer = SecretValue{}
var _ json.Marshaler = SecretValue{}

func checkMapKeys(rule Rule, value any, path string) error {
	entries := value.(map[string]any)
	required, _ := policy(rule, policyRequiredKeys)
	for _, key := range required {
		if _, exists := entries[key]; !exists {
			return fmt.Errorf("[%s] missing required map key %q", path, key)
		}
	}
	allowed, configured := policy(rule, policyAllowedKeys)
	if configured {
		for key := range entries {
			if !slices.Contains(allowed, key) {
				return fmt.Errorf("[%s] unexpected map key %q", path, key)
			}
		}
	}

	return nil
}
