package generate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/format"
	"go/token"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/depthbomb/envschema"
)

// Options controls the generated package and configuration type names.
type Options struct {
	Package string
	Type    string
}

func typeFor(rule envschema.Rule) (string, error) {
	switch rule.Kind {
	case envschema.KindString, envschema.KindEnum, envschema.KindPath, envschema.KindBase64,
		envschema.KindEmail, envschema.KindURL, envschema.KindHost, envschema.KindUUID,
		envschema.KindIP, envschema.KindHash, envschema.KindHex, envschema.KindSemVer,
		envschema.KindTimeZone, envschema.KindURI, envschema.KindMediaType, envschema.KindULID,
		envschema.KindGlob:
		return "string", nil
	case envschema.KindNumber, envschema.KindFloat:
		return "float64", nil
	case envschema.KindInt, envschema.KindBytes, envschema.KindPort:
		return "int64", nil
	case envschema.KindUInt:
		return "uint64", nil
	case envschema.KindBoolean:
		return "bool", nil
	case envschema.KindJSON:
		return "json.RawMessage", nil
	case envschema.KindDuration:
		return "time.Duration", nil
	case envschema.KindDate, envschema.KindTimestamp:
		return "time.Time", nil
	case envschema.KindCIDR:
		return "netip.Prefix", nil
	case envschema.KindRegexp:
		return "*regexp.Regexp", nil
	case envschema.KindPEM:
		return "[]byte", nil
	case envschema.KindCertificate:
		return "*x509.Certificate", nil
	case envschema.KindPrivateKey:
		return "envschema.SecretValue", nil
	case envschema.KindMACAddress:
		return "net.HardwareAddr", nil
	case envschema.KindPublicKey:
		return "envschema.PublicKeyValue", nil
	case envschema.KindCertBundle:
		return "[]*x509.Certificate", nil
	case envschema.KindBigInt:
		return "big.Int", nil
	case envschema.KindDecimal:
		return "big.Rat", nil
	case envschema.KindFileMode:
		return "fs.FileMode", nil
	case envschema.KindEndpoint, envschema.KindUnixSocket, envschema.KindTimeOfDay:
		return "string", nil
	case envschema.KindMap:
		if rule.Key == nil || rule.Item == nil {
			return "", fmt.Errorf("map has no key or value rule")
		}
		keyType, err := typeFor(*rule.Key)
		if err != nil {
			return "", err
		}
		valueType, err := typeFor(*rule.Item)
		if err != nil {
			return "", err
		}

		return "map[" + keyType + "]" + valueType, nil
	case envschema.KindCustom:
		return "", fmt.Errorf("custom type requires source import context")
	case envschema.KindSecret:
		return "envschema.SecretValue", nil
	case envschema.KindArray, envschema.KindList:
		if rule.Item == nil {
			return "", fmt.Errorf("collection has no item rule")
		}
		itemType, err := typeFor(*rule.Item)
		if err != nil {
			return "", err
		}

		return "[]" + itemType, nil
	default:
		return "", fmt.Errorf("unsupported rule kind %q", rule.Kind)
	}
}

func exportedName(name string) string {
	parts := strings.FieldsFunc(strings.ToLower(name), func(character rune) bool {
		return !unicode.IsLetter(character) && !unicode.IsDigit(character)
	})
	for index := range parts {
		runes := []rune(parts[index])
		runes[0] = unicode.ToUpper(runes[0])
		parts[index] = string(runes)
	}

	return strings.Join(parts, "")
}

func normalizedOptions(options Options) (Options, error) {
	if options.Package == "" {
		return Options{}, fmt.Errorf("generate: package name is required")
	}

	if !token.IsIdentifier(options.Package) {
		return Options{}, fmt.Errorf("generate: invalid package name %q", options.Package)
	}

	if options.Type == "" {
		options.Type = "Config"
	}

	if !token.IsIdentifier(options.Type) || !unicode.IsUpper([]rune(options.Type)[0]) {
		return Options{}, fmt.Errorf("generate: type name %q must be an exported Go identifier", options.Type)
	}

	return options, nil
}

func valueLiteral(value any) (string, error) {
	switch value := value.(type) {
	case nil:
		return "nil", nil
	case string:
		return strconv.Quote(value), nil
	case bool:
		return strconv.FormatBool(value), nil
	case int:
		return strconv.Itoa(value), nil
	case int8:
		return "int8(" + strconv.FormatInt(int64(value), 10) + ")", nil
	case int16:
		return "int16(" + strconv.FormatInt(int64(value), 10) + ")", nil
	case int32:
		return "int32(" + strconv.FormatInt(int64(value), 10) + ")", nil
	case int64:
		return "int64(" + strconv.FormatInt(value, 10) + ")", nil
	case uint:
		return "uint(" + strconv.FormatUint(uint64(value), 10) + ")", nil
	case uint8:
		return "uint8(" + strconv.FormatUint(uint64(value), 10) + ")", nil
	case uint16:
		return "uint16(" + strconv.FormatUint(uint64(value), 10) + ")", nil
	case uint32:
		return "uint32(" + strconv.FormatUint(uint64(value), 10) + ")", nil
	case uint64:
		return "uint64(" + strconv.FormatUint(value, 10) + ")", nil
	case float32:
		return "float32(" + strconv.FormatFloat(float64(value), 'g', -1, 32) + ")", nil
	case float64:
		return "float64(" + strconv.FormatFloat(value, 'g', -1, 64) + ")", nil
	case json.Number:
		return "json.Number(" + strconv.Quote(value.String()) + ")", nil
	case json.RawMessage:
		return "json.RawMessage(" + strconv.Quote(string(value)) + ")", nil
	case big.Int:
		return bigIntLiteral(value), nil
	case big.Rat:
		return "*new(big.Rat).SetFrac(" + bigIntPointerLiteral(*value.Num()) + "," + bigIntPointerLiteral(*value.Denom()) + ")", nil
	case fs.FileMode:
		return "fs.FileMode(" + strconv.FormatUint(uint64(value), 10) + ")", nil
	case net.HardwareAddr:
		parts := make([]string, len(value))
		for index, octet := range value {
			parts[index] = strconv.FormatUint(uint64(octet), 10)
		}

		return "net.HardwareAddr{" + strings.Join(parts, ",") + "}", nil
	case []any:
		parts := make([]string, len(value))
		for index, item := range value {
			literal, err := valueLiteral(item)
			if err != nil {
				return "", err
			}
			parts[index] = literal
		}

		return "[]any{" + strings.Join(parts, ",") + "}", nil
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for index, key := range keys {
			literal, err := valueLiteral(value[key])
			if err != nil {
				return "", err
			}
			parts[index] = strconv.Quote(key) + ":" + literal
		}

		return "map[string]any{" + strings.Join(parts, ",") + "}", nil
	default:
		return "", fmt.Errorf("unsupported default type %T", value)
	}
}

func bigIntLiteral(value big.Int) string {
	return "*" + bigIntPointerLiteral(value)
}

func bigIntPointerLiteral(value big.Int) string {
	bytes := value.Bytes()
	parts := make([]string, len(bytes))
	for index, octet := range bytes {
		parts[index] = strconv.FormatUint(uint64(octet), 10)
	}
	expression := "new(big.Int).SetBytes([]byte{" + strings.Join(parts, ",") + "})"
	if value.Sign() < 0 {
		expression = "new(big.Int).Neg(" + expression + ")"
	}

	return expression
}

func ruleLiteral(rule envschema.Rule) (string, error) {
	if rule.Redact {
		rule.Redact = false
		inner, err := ruleLiteral(rule)

		return inner + ".Sensitive()", err
	}
	var expression string
	switch rule.Kind {
	case envschema.KindObject:
		fields := make([]string, len(rule.Fields))
		for i, field := range rule.Fields {
			inner, err := ruleLiteral(field.Rule)
			if err != nil {
				return "", err
			}
			fields[i] = "envschema.Field(" + strconv.Quote(field.Name) + "," + inner + ")"
			if field.GoName != "" {
				fields[i] += ".Named(" + strconv.Quote(field.GoName) + ")"
			}
		}
		expression = "envschema.Object(" + strings.Join(fields, ",") + ")"
		if rule.UnknownFields {
			expression += ".AllowUnknownFields()"
		}
	case envschema.KindString:
		expression = "envschema.String()"
	case envschema.KindNumber:
		expression = "envschema.Number()"
	case envschema.KindInt:
		expression = "envschema.Int()"
	case envschema.KindFloat:
		expression = "envschema.Float()"
	case envschema.KindBoolean:
		expression = "envschema.Boolean()"
	case envschema.KindEnum:
		choices := make([]string, len(rule.Choices))
		for index, choice := range rule.Choices {
			choices[index] = strconv.Quote(choice)
		}
		expression = "envschema.Enum([]string{" + strings.Join(choices, ",") + "})"
	case envschema.KindJSON:
		expression = "envschema.JSON()"
	case envschema.KindArray, envschema.KindList:
		item, err := ruleLiteral(*rule.Item)
		if err != nil {
			return "", err
		}
		constructor := "Array"
		if rule.Kind == envschema.KindList {
			constructor = "List"
		}
		expression = "envschema." + constructor + "(" + item + ")"
	case envschema.KindDuration:
		expression = "envschema.Duration()"
	case envschema.KindDate:
		expression = "envschema.Date()"
	case envschema.KindBytes:
		expression = "envschema.Bytes()"
	case envschema.KindPath:
		expression = "envschema.Path()"
	case envschema.KindBase64:
		expression = "envschema.Base64()"
	case envschema.KindSecret:
		expression = "envschema.Secret()"
	case envschema.KindEmail:
		expression = "envschema.Email()"
	case envschema.KindPort:
		expression = "envschema.Port()"
	case envschema.KindURL:
		expression = "envschema.URL()"
	case envschema.KindHost:
		expression = "envschema.Host()"
	case envschema.KindUUID:
		expression = "envschema.UUID()"
	case envschema.KindIP:
		expression = "envschema.IPAddress()"
	case envschema.KindHash:
		expression = "envschema.Hash(envschema." + string(rule.Hash) + ")"
	case envschema.KindHex:
		expression = "envschema.Hex()"
	case envschema.KindSemVer:
		expression = "envschema.SemVer()"
	case envschema.KindTimeZone:
		expression = "envschema.TimeZone()"
	case envschema.KindUInt:
		expression = "envschema.Uint()"
	case envschema.KindCIDR:
		expression = "envschema.CIDR()"
	case envschema.KindEndpoint:
		expression = "envschema.Endpoint()"
	case envschema.KindUnixSocket:
		expression = "envschema.UnixSocket()"
	case envschema.KindTimestamp:
		expression = "envschema.Timestamp()"
	case envschema.KindTimeOfDay:
		expression = "envschema.TimeOfDay()"
	case envschema.KindRegexp:
		expression = "envschema.Regexp()"
	case envschema.KindPEM:
		expression = "envschema.PEM()"
	case envschema.KindCertificate:
		expression = "envschema.Certificate()"
	case envschema.KindPrivateKey:
		expression = "envschema.PrivateKey()"
	case envschema.KindURI:
		expression = "envschema.URI()"
	case envschema.KindMACAddress:
		expression = "envschema.MACAddress()"
	case envschema.KindPublicKey:
		expression = "envschema.PublicKey()"
	case envschema.KindCertBundle:
		expression = "envschema.CertificateBundle()"
	case envschema.KindBigInt:
		expression = "envschema.BigInt()"
	case envschema.KindDecimal:
		expression = "envschema.Decimal()"
	case envschema.KindMediaType:
		expression = "envschema.MediaType()"
	case envschema.KindFileMode:
		expression = "envschema.FileMode()"
	case envschema.KindULID:
		expression = "envschema.ULID()"
	case envschema.KindGlob:
		expression = "envschema.Glob()"
	case envschema.KindMap:
		key, err := ruleLiteral(*rule.Key)
		if err != nil {
			return "", err
		}
		value, err := ruleLiteral(*rule.Item)
		if err != nil {
			return "", err
		}
		expression = "envschema.Map(" + key + "," + value + ")"
	case envschema.KindCustom:
		expression = "envschema.CustomNamed(" + strconv.Quote(rule.CustomPackage) + "," + strconv.Quote(rule.CustomName) + ")"
	default:
		return "", fmt.Errorf("unsupported rule kind %q", rule.Kind)
	}

	if !rule.Required {
		expression += ".Optional()"
	}
	if rule.HasDefault {
		literal, err := valueLiteral(rule.Default)
		if err != nil {
			return "", err
		}
		expression += ".DefaultTo(" + literal + ")"
	}
	if rule.Trim {
		expression += ".Trimmed()"
	}
	if rule.Pattern != "" {
		expression += ".Matching(" + strconv.Quote(rule.Pattern) + ")"
	}
	for _, field := range rule.QueryFields {
		inner, err := ruleLiteral(field.Rule)
		if err != nil {
			return "", err
		}
		expression += ".QueryParameter(" + strconv.Quote(field.Name) + "," + inner + ")"
	}
	if rule.MinLength != nil {
		expression += ".WithMinLength(" + strconv.Itoa(*rule.MinLength) + ")"
	}
	if rule.MaxLength != nil {
		expression += ".WithMaxLength(" + strconv.Itoa(*rule.MaxLength) + ")"
	}
	if rule.EmptyAllowed {
		expression += ".AllowEmpty()"
	}
	if rule.Prefix != "" {
		expression += ".WithPrefix(" + strconv.Quote(rule.Prefix) + ")"
	}
	if rule.Suffix != "" {
		expression += ".WithSuffix(" + strconv.Quote(rule.Suffix) + ")"
	}
	if rule.ASCII {
		expression += ".ASCIIOnly()"
	}
	if rule.Printable {
		expression += ".PrintableOnly()"
	}
	if rule.NoWhitespace {
		expression += ".WithoutWhitespace()"
	}
	if rule.NoSurroundingSpace {
		expression += ".WithoutSurroundingWhitespace()"
	}
	if rule.RuneLength {
		expression += ".CountRunes()"
	}
	if rule.Lowercase {
		expression += ".LowercaseOnly()"
	}
	if rule.Uppercase {
		expression += ".UppercaseOnly()"
	}
	if rule.Min != nil {
		expression += ".AtLeast(" + strconv.FormatFloat(*rule.Min, 'g', -1, 64) + ")"
	}
	if rule.Max != nil {
		expression += ".AtMost(" + strconv.FormatFloat(*rule.Max, 'g', -1, 64) + ")"
	}
	if rule.ExclusiveMin != nil {
		expression += ".GreaterThan(" + strconv.FormatFloat(*rule.ExclusiveMin, 'g', -1, 64) + ")"
	}
	if rule.ExclusiveMax != nil {
		expression += ".LessThan(" + strconv.FormatFloat(*rule.ExclusiveMax, 'g', -1, 64) + ")"
	}
	if rule.Multiple != nil {
		expression += ".MultipleOf(" + strconv.FormatFloat(*rule.Multiple, 'g', -1, 64) + ")"
	}
	if rule.RejectZero {
		expression += ".NonZero()"
	}
	if rule.Positive {
		expression += ".PositiveOnly()"
	}
	if rule.Negative {
		expression += ".NegativeOnly()"
	}
	if rule.MinDate != "" {
		expression += ".StartingAt(" + strconv.Quote(rule.MinDate) + ")"
	}
	if rule.MaxDate != "" {
		expression += ".EndingAt(" + strconv.Quote(rule.MaxDate) + ")"
	}
	if rule.MinDuration != "" {
		value, _ := time.ParseDuration(rule.MinDuration)
		expression += ".AtLeastDuration(time.Duration(" + strconv.FormatInt(int64(value), 10) + "))"
	}
	if rule.MaxDuration != "" {
		value, _ := time.ParseDuration(rule.MaxDuration)
		expression += ".AtMostDuration(time.Duration(" + strconv.FormatInt(int64(value), 10) + "))"
	}
	if rule.Separator != "" && (rule.Kind != envschema.KindMap || rule.Separator != ",") {
		expression += ".SeparatedBy(" + strconv.Quote(rule.Separator) + ")"
	}
	if !rule.ListTrim {
		expression += ".PreserveWhitespace()"
	}
	if rule.Unique {
		expression += ".UniqueItems()"
	}
	if rule.MinItems != nil {
		expression += ".AtLeastItems(" + strconv.Itoa(*rule.MinItems) + ")"
	}
	if rule.MaxItems != nil {
		expression += ".AtMostItems(" + strconv.Itoa(*rule.MaxItems) + ")"
	}
	if rule.KeyValueSeparator != "" && rule.Kind == envschema.KindMap && rule.KeyValueSeparator != "=" {
		expression += ".KeyValueSeparatedBy(" + strconv.Quote(rule.KeyValueSeparator) + ")"
	}
	if rule.PathKind == envschema.PathFile {
		expression += ".File()"
	} else if rule.PathKind == envschema.PathDirectory {
		expression += ".Directory()"
	}
	if rule.Exists {
		expression += ".Existing()"
	}
	if rule.Absolute != nil {
		if *rule.Absolute {
			expression += ".AbsoluteOnly()"
		} else {
			expression += ".RelativeOnly()"
		}
	}
	if rule.URLSafe {
		expression += ".URLSafeEncoding()"
	}
	if rule.Padding != "" && rule.Padding != envschema.PaddingOptional {
		expression += ".WithPadding(envschema.Padding" + strings.ToUpper(string(rule.Padding[:1])) + string(rule.Padding[1:]) + ")"
	}
	if rule.IPVersion != "" {
		expression += ".IPVersionIs(envschema.IPv" + string(rule.IPVersion) + ")"
	}
	if rule.UUID != "" && rule.UUID != envschema.UUIDAny {
		expression += ".UUIDVersionIs(envschema.UUIDv" + string(rule.UUID) + ")"
	}
	if len(rule.Schemes) != 0 {
		values := make([]string, len(rule.Schemes))
		for index, scheme := range rule.Schemes {
			values[index] = strconv.Quote(scheme)
		}
		expression += ".WithSchemes(" + strings.Join(values, ",") + ")"
	}
	if rule.URLCredentials != nil {
		if *rule.URLCredentials {
			expression += ".RequireCredentials()"
		} else {
			expression += ".WithoutCredentials()"
		}
	}
	if rule.URLPort != nil {
		if *rule.URLPort {
			expression += ".RequirePort()"
		} else {
			expression += ".WithoutPort()"
		}
	}
	if rule.URLQuery != nil {
		if *rule.URLQuery {
			expression += ".RequireQuery()"
		} else {
			expression += ".WithoutQuery()"
		}
	}
	if rule.URLFragment != nil {
		if *rule.URLFragment {
			expression += ".RequireFragment()"
		} else {
			expression += ".WithoutFragment()"
		}
	}
	if rule.EnumCaseInsensitive {
		expression += ".CaseInsensitive()"
	}
	if len(rule.Aliases) != 0 {
		aliases := make([]string, 0, len(rule.Aliases))
		for alias := range rule.Aliases {
			aliases = append(aliases, alias)
		}
		sort.Strings(aliases)
		for _, alias := range aliases {
			expression += ".Alias(" + strconv.Quote(alias) + "," + strconv.Quote(rule.Aliases[alias]) + ")"
		}
	}
	if rule.UTC {
		expression += ".UTCOnly()"
	}
	if rule.StrictBoolean {
		expression += ".Strict()"
	}
	policyNames := make([]string, 0, len(rule.Policies))
	for name := range rule.Policies {
		policyNames = append(policyNames, name)
	}
	sort.Strings(policyNames)
	for _, name := range policyNames {
		arguments := []string{strconv.Quote(name)}
		for _, value := range rule.Policies[name] {
			arguments = append(arguments, strconv.Quote(value))
		}
		expression += ".WithPolicy(" + strings.Join(arguments, ",") + ")"
	}

	return expression, nil
}

func schemaLiteral(schema envschema.Schema) (string, error) {
	variables := make([]string, len(schema.Variables))
	for index, variable := range schema.Variables {
		rule, err := ruleLiteral(variable.Rule)
		if err != nil {
			return "", fmt.Errorf("%s: %w", variable.Name, err)
		}
		constructor := "envschema.Var(" + strconv.Quote(variable.Name) + "," + rule + ")"
		if variable.GoName != "" {
			constructor = "envschema.Named(" + strconv.Quote(variable.Name) + "," + strconv.Quote(variable.GoName) + "," + rule + ")"
		}
		for _, fallback := range variable.Fallbacks {
			constructor += ".FallbackTo(" + strconv.Quote(fallback) + ")"
		}
		if variable.Deprecation != "" {
			constructor += ".Deprecated(" + strconv.Quote(variable.Deprecation) + ")"
		}
		variables[index] = constructor
	}
	var expression strings.Builder
	expression.WriteString("envschema.Must(")
	if len(variables) != 0 {
		expression.WriteString("\n" + strings.Join(variables, ",\n") + ",\n")
	}
	expression.WriteString(")")
	for _, constraint := range schema.Constraints {
		args := make([]string, len(constraint.Names))
		for index, name := range constraint.Names {
			args[index] = strconv.Quote(name)
		}
		switch constraint.Kind {
		case envschema.ConstraintRequiredWhen, envschema.ConstraintForbiddenWhen, envschema.ConstraintRequiredUnless:
			method := map[envschema.ConstraintKind]string{
				envschema.ConstraintRequiredWhen:   "RequiredWhen",
				envschema.ConstraintForbiddenWhen:  "ForbiddenWhen",
				envschema.ConstraintRequiredUnless: "RequiredUnless",
			}[constraint.Kind]
			expression.WriteString("." + method + "(" + args[0] + "," + strconv.Quote(constraint.Value) + "," + strings.Join(args[1:], ",") + ")")
		default:
			method := map[envschema.ConstraintKind]string{
				envschema.ConstraintExactlyOne:        "ExactlyOneOf",
				envschema.ConstraintAtLeastOne:        "AtLeastOneOf",
				envschema.ConstraintMutuallyExclusive: "MutuallyExclusive",
				envschema.ConstraintRequiredTogether:  "RequiredTogether",
				envschema.ConstraintRequiredIfPresent: "RequiredIfPresent",
				envschema.ConstraintEqualValues:       "EqualValues",
				envschema.ConstraintDifferentValues:   "DifferentValues",
				envschema.ConstraintLessThanVariable:  "LessThanVariable",
				envschema.ConstraintTLSKeyPair:        "TLSKeyPair",
			}[constraint.Kind]
			expression.WriteString("." + method + "(" + strings.Join(args, ",") + ")")
		}
	}

	return expression.String(), nil
}

func sourceTypeFor(rule envschema.Rule, imports map[string]string) (string, error) {
	if rule.Redact {
		rule.Redact = false
		inner, err := sourceTypeFor(rule, imports)

		return "envschema.Protected[" + inner + "]", err
	}
	if rule.Kind == envschema.KindObject {
		var result strings.Builder
		result.WriteString("struct {")
		for _, field := range rule.Fields {
			inner, err := sourceTypeFor(field.Rule, imports)
			if err != nil {
				return "", err
			}
			if !field.Rule.Required && !field.Rule.HasDefault && !strings.HasPrefix(inner, "*") {
				inner = "*" + inner
			}
			result.WriteString(envschema.ObjectFieldName(field) + " " + inner + " " + strconv.Quote("json:"+strconv.Quote(field.Name)) + ";")
		}
		result.WriteString("}")

		return result.String(), nil
	}
	if rule.Kind == envschema.KindCustom {
		alias := "custom"
		for index := 0; ; index++ {
			candidate := alias
			if index != 0 {
				candidate += strconv.Itoa(index)
			}
			path, exists := imports[candidate]
			if !exists || path == rule.CustomPackage {
				imports[candidate] = rule.CustomPackage

				return candidate + "." + rule.CustomName, nil
			}
		}
	}
	if rule.Kind == envschema.KindArray || rule.Kind == envschema.KindList {
		item, err := sourceTypeFor(*rule.Item, imports)
		if err != nil {
			return "", err
		}

		return "[]" + item, nil
	}
	if rule.Kind == envschema.KindMap {
		key, err := sourceTypeFor(*rule.Key, imports)
		if err != nil {
			return "", err
		}
		value, err := sourceTypeFor(*rule.Item, imports)
		if err != nil {
			return "", err
		}

		return "map[" + key + "]" + value, nil
	}

	return typeFor(rule)
}

func defaultImports(value any, imports map[string]string) {
	switch value := value.(type) {
	case json.Number, json.RawMessage:
		imports["json"] = "encoding/json"
	case big.Int, big.Rat:
		imports["big"] = "math/big"
	case fs.FileMode:
		imports["fs"] = "io/fs"
	case net.HardwareAddr:
		imports["net"] = "net"
	case []any:
		for _, item := range value {
			defaultImports(item, imports)
		}
	case map[string]any:
		for _, item := range value {
			defaultImports(item, imports)
		}
	}
}

func ruleDefaultImports(rule envschema.Rule, imports map[string]string) {
	for _, field := range rule.QueryFields {
		ruleDefaultImports(field.Rule, imports)
	}
	for _, field := range rule.Fields {
		ruleDefaultImports(field.Rule, imports)
	}
	if rule.HasDefault {
		defaultImports(rule.Default, imports)
	}

	if rule.Item != nil {
		ruleDefaultImports(*rule.Item, imports)
	}

	if rule.Key != nil {
		ruleDefaultImports(*rule.Key, imports)
	}
}

func constraintsParseValues(schema envschema.Schema) bool {
	for _, constraint := range schema.Constraints {
		switch constraint.Kind {
		case envschema.ConstraintRequiredWhen, envschema.ConstraintForbiddenWhen, envschema.ConstraintRequiredUnless,
			envschema.ConstraintEqualValues, envschema.ConstraintDifferentValues, envschema.ConstraintLessThanVariable:
			return true
		}
	}

	return false
}

// Source returns formatted Go source for a validated schema.
func Source(schema envschema.Schema, options Options) ([]byte, error) {
	if err := schema.Validate(); err != nil {
		return nil, err
	}

	options, err := normalizedOptions(options)
	if err != nil {
		return nil, err
	}

	types := make([]string, len(schema.Variables))
	optionalPointers := make([]bool, len(schema.Variables))
	names := make([]string, len(schema.Variables))
	imports := map[string]string{"envschema": reflect.TypeFor[envschema.Schema]().PkgPath()}
	seenNames := make(map[string]string, len(schema.Variables))
	for index, variable := range schema.Variables {
		ruleDefaultImports(variable.Rule, imports)
		name := variable.GoName
		if name == "" {
			name = exportedName(variable.Name)
		}
		if !token.IsIdentifier(name) || !unicode.IsUpper([]rune(name)[0]) {
			return nil, fmt.Errorf("generate: Go field name %q for %s is not exported", name, variable.Name)
		}
		if prior, ok := seenNames[name]; ok {
			return nil, fmt.Errorf("generate: %s and %s both map to Go field %s", prior, variable.Name, name)
		}
		seenNames[name] = variable.Name
		names[index] = name

		goType, typeErr := sourceTypeFor(variable.Rule, imports)
		if typeErr != nil {
			return nil, fmt.Errorf("generate: %s: %w", variable.Name, typeErr)
		}
		if !variable.Rule.Required && !variable.Rule.HasDefault {
			if !strings.HasPrefix(goType, "*") {
				goType = "*" + goType
				optionalPointers[index] = true
			}
		}
		types[index] = goType
		if strings.Contains(goType, "json.") {
			imports["json"] = "encoding/json"
		}
		if strings.Contains(goType, "time.") {
			imports["time"] = "time"
		}
		if strings.Contains(goType, "netip.") {
			imports["netip"] = "net/netip"
		}
		if strings.Contains(goType, "regexp.") {
			imports["regexp"] = "regexp"
		}
		if strings.Contains(goType, "x509.") {
			imports["x509"] = "crypto/x509"
		}
		if strings.Contains(goType, "net.") {
			imports["net"] = "net"
		}
		if strings.Contains(goType, "big.") {
			imports["big"] = "math/big"
		}
		if strings.Contains(goType, "fs.") {
			imports["fs"] = "io/fs"
		}
	}

	encodedSchema, err := schemaLiteral(schema)
	if err != nil {
		return nil, fmt.Errorf("generate: encode schema: %w", err)
	}

	var source bytes.Buffer
	source.Grow(len(encodedSchema) + len(schema.Variables)*400 + 512)
	fmt.Fprintf(&source, "// Code generated by envschema. DO NOT EDIT.\n\npackage %s\n\n", options.Package)
	source.WriteString("import (\n")
	for _, name := range []string{"x509", "json", "fs", "big", "net", "netip", "regexp", "time"} {
		if path, ok := imports[name]; ok {
			fmt.Fprintf(&source, "\t%q\n", path)
		}
	}
	customImports := make([]string, 0)
	for name := range imports {
		if strings.HasPrefix(name, "custom") {
			customImports = append(customImports, name)
		}
	}
	sort.Strings(customImports)
	for _, name := range customImports {
		fmt.Fprintf(&source, "\t%s %q\n", name, imports[name])
	}
	if len(imports) > 1 {
		source.WriteString("\n")
	}
	fmt.Fprintf(&source, "\t%q\n", imports["envschema"])
	source.WriteString(")\n\n")
	fmt.Fprintf(&source, "var generatedSchema = %s\n\n", encodedSchema)
	fmt.Fprintf(&source, "type %s struct {\n", options.Type)
	for index, variable := range schema.Variables {
		fmt.Fprintf(&source, "\t%s %s `env:%s`\n", names[index], types[index], strconv.Quote(variable.Name))
	}
	source.WriteString("}\n\n")
	fmt.Fprintf(&source, "func LoadFrom(lookup envschema.LookupFunc) (%s, error) {\n", options.Type)
	fmt.Fprintf(&source, "\tvar config %s\n", options.Type)
	reuseValues := constraintsParseValues(schema)
	if reuseValues {
		source.WriteString("\tvalues, err := envschema.LoadFrom(generatedSchema, lookup)\n")
		fmt.Fprintf(&source, "\tif err != nil {\n\t\treturn %s{}, err\n\t}\n", options.Type)
		for _, variable := range schema.Variables {
			if variable.Rule.Kind == envschema.KindCustom && !variable.Rule.Redact {
				source.WriteString("\tcustomLookup := func(name string) (string, bool) {\n\t\tvalue, present := values[name].(string)\n\n\t\treturn value, present\n\t}\n")
				break
			}
		}
	} else if len(schema.Constraints) != 0 {
		source.WriteString("\tif err := envschema.ValidateConstraints(generatedSchema, lookup); err != nil {\n")
		fmt.Fprintf(&source, "\t\treturn %s{}, err\n\t}\n", options.Type)
	}
	for index, variable := range schema.Variables {
		baseType := types[index]
		if optionalPointers[index] {
			baseType = strings.TrimPrefix(baseType, "*")
		}
		if reuseValues && (variable.Rule.Kind != envschema.KindCustom || variable.Rule.Redact) {
			optional := !variable.Rule.Required && !variable.Rule.HasDefault
			if optional {
				fmt.Fprintf(&source, "\tif _, present := values[%q]; present {\n", variable.Name)
			}
			fmt.Fprintf(&source, "\tvalue%d, err := envschema.ValueAs[%s](values, %q)\n", index, baseType, variable.Name)
			fmt.Fprintf(&source, "\tif err != nil {\n\t\treturn %s{}, err\n\t}\n", options.Type)
			address := ""
			if optionalPointers[index] {
				address = "&"
			}
			fmt.Fprintf(&source, "\tconfig.%s = %svalue%d\n", names[index], address, index)
			if optional {
				source.WriteString("\t}\n")
			}
			continue
		}
		reader := "envschema.Read"
		lookupName := "lookup"
		if variable.Rule.Kind == envschema.KindCustom && !variable.Rule.Redact {
			reader = "envschema.ReadText"
			if reuseValues {
				lookupName = "customLookup"
			}
		}
		fallbacks := ""
		if len(variable.Fallbacks) != 0 && !reuseValues {
			if variable.Rule.Kind == envschema.KindCustom && !variable.Rule.Redact {
				reader = "envschema.ReadTextWithFallbacks"
			} else {
				reader = "envschema.ReadWithFallbacks"
			}
			quoted := make([]string, len(variable.Fallbacks))
			for fallbackIndex, fallback := range variable.Fallbacks {
				quoted[fallbackIndex] = strconv.Quote(fallback)
			}
			fallbacks = ", []string{" + strings.Join(quoted, ",") + "}"
		}
		if optionalPointers[index] {
			fmt.Fprintf(&source, "\tvalue%d, present%d, err := %s[%s](generatedSchema.Variables[%d].Rule, %q%s, %s)\n", index, index, reader, baseType, index, variable.Name, fallbacks, lookupName)
			fmt.Fprintf(&source, "\tif err != nil {\n\t\treturn %s{}, err\n\t}\n", options.Type)
			fmt.Fprintf(&source, "\tif present%d {\n\t\tconfig.%s = &value%d\n\t}\n", index, names[index], index)
		} else {
			fmt.Fprintf(&source, "\tvalue%d, _, err := %s[%s](generatedSchema.Variables[%d].Rule, %q%s, %s)\n", index, reader, baseType, index, variable.Name, fallbacks, lookupName)
			fmt.Fprintf(&source, "\tif err != nil {\n\t\treturn %s{}, err\n\t}\n", options.Type)
			fmt.Fprintf(&source, "\tconfig.%s = value%d\n", names[index], index)
		}
	}
	source.WriteString("\n\treturn config, nil\n}\n\n")
	fmt.Fprintf(&source, "func Load() (%s, error) {\n", options.Type)
	source.WriteString("\tlookup, err := envschema.LookupEnvFiles()\n")
	source.WriteString("\tif err != nil {\n")
	fmt.Fprintf(&source, "\t\treturn %s{}, err\n\t}\n\n", options.Type)
	source.WriteString("\treturn LoadFrom(lookup)\n}\n")

	fmt.Fprintf(&source, "\nfunc LoadSource(input envschema.Source, prefixes ...string) (%s,error) {\n", options.Type)
	fmt.Fprintf(&source, "if err := envschema.ValidateKnownVariables(generatedSchema,input,prefixes...); err != nil { return %s{},err }\n", options.Type)
	source.WriteString("return LoadFrom(input.Lookup)\n}\n")

	formatted, err := format.Source(source.Bytes())
	if err != nil {
		return nil, fmt.Errorf("generate: format source: %w\n%s", err, source.String())
	}

	return formatted, nil
}

// File atomically writes generated source to filename.
func File(filename string, schema envschema.Schema, options Options) error {
	source, err := Source(schema, options)
	if err != nil {
		return err
	}

	directory := filepath.Dir(filename)
	temporary, err := os.CreateTemp(directory, ".envschema-*.go")
	if err != nil {
		return fmt.Errorf("generate: create temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)

	if _, err := temporary.Write(source); err != nil {
		temporary.Close()

		return fmt.Errorf("generate: write temporary file: %w", err)
	}

	if err := temporary.Close(); err != nil {
		return fmt.Errorf("generate: close temporary file: %w", err)
	}

	if err := os.Rename(temporaryName, filename); err != nil {
		return fmt.Errorf("generate: replace %s: %w", filename, err)
	}

	return nil
}
