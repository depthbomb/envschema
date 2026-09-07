package envschema

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	policyAllowedKeys          = "json.allowedKeys"
	policyAllowEmptyHost       = "endpoint.allowEmptyHost"
	policyAllowIPAddress       = "host.allowIPAddress"
	policyAllowRelative        = "url.allowRelativeReference"
	policyAllowTrailingDot     = "host.allowTrailingDot"
	policyBase                 = "number.base"
	policyCACertificate        = "certificate.ca"
	policyCanonicalCIDR        = "cidr.canonical"
	policyCanonicalURI         = "url.canonical"
	policyCaseFoldUnique       = "collection.caseFoldUnique"
	policyCertificateHostname  = "certificate.hostname"
	policyCertificateUsage     = "certificate.usage"
	policyCleanPath            = "path.clean"
	policyContainedBy          = "cidr.containedBy"
	policyContaining           = "string.containing"
	policyContainsAddresses    = "cidr.containsAddresses"
	policyCSV                  = "collection.csv"
	policyDateOnly             = "date.only"
	policyDecodedMax           = "base64.decodedMax"
	policyDecodedMin           = "base64.decodedMin"
	policyDistinctMin          = "collection.distinctMin"
	policyEndpointHostType     = "endpoint.hostType"
	policyEndpointValidateHost = "endpoint.validateHost"
	policyEqualFold            = "string.equalFold"
	policyExecutable           = "path.executable"
	policyExtensions           = "path.extensions"
	policyFalseValues          = "boolean.falseValues"
	policyFractionalSeconds    = "time.fractionalSeconds"
	policyGlob                 = "path.glob"
	policyHashPrefix           = "hash.prefix"
	policyHostSuffix           = "host.suffix"
	policyIPClass              = "ip.class"
	policyJSONDepth            = "json.maxDepth"
	policyJSONKind             = "json.kind"
	policyJSONSize             = "json.maxBytes"
	policyJSONUniqueKeys       = "json.uniqueKeys"
	policyLabelsMax            = "host.labelsMax"
	policyLabelsMin            = "host.labelsMin"
	policyLocalPath            = "path.local"
	policyMediaParameters      = "media.parameters"
	policyMinRSA               = "key.minRSA"
	policyNoControl            = "string.noControl"
	policyNonMaxUUID           = "uuid.nonMax"
	policyNonNilUUID           = "uuid.nonNil"
	policyNonZeroPort          = "endpoint.nonZeroPort"
	policyNotContaining        = "string.notContaining"
	policyNotExisting          = "path.notExisting"
	policyOpaqueForbidden      = "url.noOpaque"
	policyPathPresence         = "url.path"
	policyPathPrefix           = "url.pathPrefix"
	policyPEMBlockTypes        = "pem.blockTypes"
	policyPEMHeaders           = "pem.headers"
	policyPKCS8                = "key.pkcs8"
	policyPortBounds           = "endpoint.portBounds"
	policyPrefixBounds         = "cidr.prefixBounds"
	policyPrivateKeyAlgorithms = "key.algorithms"
	policyQueryKeys            = "url.queryKeys"
	policyRejectEmptyItems     = "collection.rejectEmptyItems"
	policyRejectEmptyKeys      = "map.rejectEmptyKeys"
	policyRejectEmptyValues    = "map.rejectEmptyValues"
	policyRequireHost          = "url.requireHost"
	policyRequiredKeys         = "json.requiredKeys"
	policyRequireOffset        = "timestamp.requireOffset"
	policyRequireTrailingDot   = "host.requireTrailingDot"
	policyRFCVariant           = "uuid.rfcVariant"
	policySemVerBuild          = "semver.build"
	policySemVerMax            = "semver.max"
	policySemVerMin            = "semver.min"
	policySemVerPrerelease     = "semver.prerelease"
	policySingleLine           = "string.singleLine"
	policySorted               = "collection.sorted"
	policySymlink              = "path.symlink"
	policyTimePrecision        = "timestamp.precision"
	policyTimeSeconds          = "time.seconds"
	policyTrueValues           = "boolean.trueValues"
	policyURIHosts             = "url.hosts"
	policyUserPassword         = "url.noUserPassword"
	policyUTF8                 = "string.utf8"
	policyUUIDVersions         = "uuid.versions"
	policyValidAt              = "certificate.validAt"
	policyValidFor             = "certificate.validFor"
	policyWithin               = "path.within"
)

func (rule Rule) withAdditionalPolicy(name string, value string) Rule {
	values := append([]string(nil), rule.Policies[name]...)
	if !slices.Contains(values, value) {
		values = append(values, value)
	}

	return rule.WithPolicy(name, values...)
}

// WithPolicy returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithPolicy(name string, values ...string) Rule {
	policies := make(map[string][]string, len(rule.Policies)+1)
	for key, existing := range rule.Policies {
		policies[key] = append([]string(nil), existing...)
	}
	policies[name] = append([]string(nil), values...)
	rule.Policies = policies

	return rule
}

// Containing returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) Containing(values ...string) Rule {
	return rule.WithPolicy(policyContaining, values...)
}

// NotContaining returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) NotContaining(values ...string) Rule {
	return rule.WithPolicy(policyNotContaining, values...)
}

// ValidUTF8 returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) ValidUTF8() Rule { return rule.WithPolicy(policyUTF8) }

// WithoutControlCharacters returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutControlCharacters() Rule { return rule.WithPolicy(policyNoControl) }

// SingleLine returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) SingleLine() Rule { return rule.WithPolicy(policySingleLine) }

// EqualFold returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) EqualFold(value string) Rule { return rule.WithPolicy(policyEqualFold, value) }

// WithByteLengthBetween returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithByteLengthBetween(minimum int, maximum int) Rule {
	rule.MinLength = &minimum
	rule.MaxLength = &maximum
	rule.RuneLength = false

	return rule
}

// Base returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) Base(value int) Rule { return rule.WithPolicy(policyBase, strconv.Itoa(value)) }

// TrueValues returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) TrueValues(values ...string) Rule {
	return rule.WithPolicy(policyTrueValues, values...)
}

// FalseValues returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) FalseValues(values ...string) Rule {
	return rule.WithPolicy(policyFalseValues, values...)
}

// ObjectOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) ObjectOnly() Rule { return rule.withAdditionalPolicy(policyJSONKind, "object") }

// ArrayOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) ArrayOnly() Rule { return rule.withAdditionalPolicy(policyJSONKind, "array") }

// ScalarOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) ScalarOnly() Rule { return rule.withAdditionalPolicy(policyJSONKind, "scalar") }

// WithoutNull returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutNull() Rule { return rule.withAdditionalPolicy(policyJSONKind, "nonNull") }

// RequiredKeys returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RequiredKeys(values ...string) Rule {
	return rule.WithPolicy(policyRequiredKeys, values...)
}

// AllowedKeys returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AllowedKeys(values ...string) Rule {
	return rule.WithPolicy(policyAllowedKeys, values...)
}

// AtMostBytes returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AtMostBytes(value int) Rule {
	return rule.WithPolicy(policyJSONSize, strconv.Itoa(value))
}

// AtMostDepth returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AtMostDepth(value int) Rule {
	return rule.WithPolicy(policyJSONDepth, strconv.Itoa(value))
}

// UniqueObjectKeys returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) UniqueObjectKeys() Rule { return rule.WithPolicy(policyJSONUniqueKeys) }

// CSV returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) CSV() Rule { return rule.WithPolicy(policyCSV) }

// RejectEmptyItems returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RejectEmptyItems() Rule { return rule.WithPolicy(policyRejectEmptyItems) }

// AllowEmptyItems returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AllowEmptyItems() Rule {
	policies := make(map[string][]string, len(rule.Policies))
	for key, values := range rule.Policies {
		if key != policyRejectEmptyItems {
			policies[key] = append([]string(nil), values...)
		}
	}
	rule.Policies = policies

	return rule
}

// RejectEmptyKeys returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RejectEmptyKeys() Rule { return rule.WithPolicy(policyRejectEmptyKeys) }

// RejectEmptyValues returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RejectEmptyValues() Rule { return rule.WithPolicy(policyRejectEmptyValues) }

// CaseInsensitiveUniqueItems returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) CaseInsensitiveUniqueItems() Rule { return rule.WithPolicy(policyCaseFoldUnique) }

// AtLeastDistinctItems returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AtLeastDistinctItems(value int) Rule {
	return rule.WithPolicy(policyDistinctMin, strconv.Itoa(value))
}

// Sorted returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) Sorted() Rule { return rule.WithPolicy(policySorted, "weak") }

// StrictlySorted returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) StrictlySorted() Rule { return rule.WithPolicy(policySorted, "strict") }

// LocalOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) LocalOnly() Rule { return rule.WithPolicy(policyLocalPath) }

// Within returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) Within(root string) Rule { return rule.WithPolicy(policyWithin, root) }

// WithExtensions returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithExtensions(values ...string) Rule {
	return rule.WithPolicy(policyExtensions, values...)
}

// MatchingGlob returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) MatchingGlob(value string) Rule { return rule.WithPolicy(policyGlob, value) }

// SymlinkForbidden returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) SymlinkForbidden() Rule { return rule.WithPolicy(policySymlink, "forbidden") }

// SymlinkRequired returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) SymlinkRequired() Rule { return rule.WithPolicy(policySymlink, "required") }

// CleanOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) CleanOnly() Rule { return rule.WithPolicy(policyCleanPath) }

// NotExisting returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) NotExisting() Rule { return rule.WithPolicy(policyNotExisting) }

// Executable returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) Executable() Rule { return rule.WithPolicy(policyExecutable) }

// RequireHost returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RequireHost() Rule { return rule.WithPolicy(policyRequireHost) }

// WithHosts returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithHosts(values ...string) Rule { return rule.WithPolicy(policyURIHosts, values...) }

// WithHostSuffix returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithHostSuffix(value string) Rule { return rule.WithPolicy(policyHostSuffix, value) }

// RequirePath returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RequirePath() Rule { return rule.WithPolicy(policyPathPresence, "required") }

// WithoutPath returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutPath() Rule { return rule.WithPolicy(policyPathPresence, "forbidden") }

// WithPathPrefix returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithPathPrefix(value string) Rule { return rule.WithPolicy(policyPathPrefix, value) }

// WithoutOpaqueForm returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutOpaqueForm() Rule { return rule.WithPolicy(policyOpaqueForbidden) }

// AllowRelativeReference returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AllowRelativeReference() Rule { return rule.WithPolicy(policyAllowRelative) }

// RequireQueryKeys returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RequireQueryKeys(values ...string) Rule {
	return rule.WithPolicy(policyQueryKeys, values...)
}

// WithoutUserPassword returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutUserPassword() Rule { return rule.WithPolicy(policyUserPassword) }

// CanonicalOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) CanonicalOnly() Rule {
	if rule.Kind == KindURL || rule.Kind == KindURI {
		return rule.WithPolicy(policyCanonicalURI)
	}

	return rule.WithPolicy(policyCanonicalCIDR)
}

// AllowTrailingDot returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AllowTrailingDot() Rule { return rule.WithPolicy(policyAllowTrailingDot) }

// RequireTrailingDot returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RequireTrailingDot() Rule { return rule.WithPolicy(policyRequireTrailingDot) }

// AtLeastLabels returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AtLeastLabels(value int) Rule {
	return rule.WithPolicy(policyLabelsMin, strconv.Itoa(value))
}

// AtMostLabels returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AtMostLabels(value int) Rule {
	return rule.WithPolicy(policyLabelsMax, strconv.Itoa(value))
}

// WithDomainSuffix returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithDomainSuffix(value string) Rule { return rule.WithPolicy(policyHostSuffix, value) }

// AllowIPAddress returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AllowIPAddress() Rule { return rule.WithPolicy(policyAllowIPAddress) }

// PrivateOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) PrivateOnly() Rule { return rule.withAdditionalPolicy(policyIPClass, "private") }

// PublicOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) PublicOnly() Rule { return rule.withAdditionalPolicy(policyIPClass, "public") }

// LoopbackOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) LoopbackOnly() Rule { return rule.withAdditionalPolicy(policyIPClass, "loopback") }

// WithoutLoopback returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutLoopback() Rule {
	return rule.withAdditionalPolicy(policyIPClass, "notLoopback")
}

// WithoutUnspecified returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutUnspecified() Rule {
	return rule.withAdditionalPolicy(policyIPClass, "notUnspecified")
}

// MulticastOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) MulticastOnly() Rule { return rule.withAdditionalPolicy(policyIPClass, "multicast") }

// WithoutMulticast returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutMulticast() Rule {
	return rule.withAdditionalPolicy(policyIPClass, "notMulticast")
}

// LinkLocalOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) LinkLocalOnly() Rule { return rule.withAdditionalPolicy(policyIPClass, "linkLocal") }

// WithoutLinkLocal returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutLinkLocal() Rule {
	return rule.withAdditionalPolicy(policyIPClass, "notLinkLocal")
}

// PrefixLengthBetween returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) PrefixLengthBetween(minimum int, maximum int) Rule {
	return rule.WithPolicy(policyPrefixBounds, strconv.Itoa(minimum), strconv.Itoa(maximum))
}

// ContainingAddresses returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) ContainingAddresses(values ...string) Rule {
	return rule.WithPolicy(policyContainsAddresses, values...)
}

// ContainedBy returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) ContainedBy(value string) Rule { return rule.WithPolicy(policyContainedBy, value) }

// NonZeroPort returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) NonZeroPort() Rule { return rule.WithPolicy(policyNonZeroPort) }

// PortBetween returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) PortBetween(minimum int, maximum int) Rule {
	return rule.WithPolicy(policyPortBounds, strconv.Itoa(minimum), strconv.Itoa(maximum))
}

// IPOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) IPOnly() Rule { return rule.WithPolicy(policyEndpointHostType, "ip") }

// HostnameOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) HostnameOnly() Rule { return rule.WithPolicy(policyEndpointHostType, "hostname") }

// ValidateHostname returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) ValidateHostname() Rule { return rule.WithPolicy(policyEndpointValidateHost) }

// AllowEmptyHost returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AllowEmptyHost() Rule { return rule.WithPolicy(policyAllowEmptyHost) }

// Versions returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) Versions(values ...UUIDVersion) Rule {
	versions := make([]string, len(values))
	for index := range values {
		versions[index] = string(values[index])
	}

	return rule.WithPolicy(policyUUIDVersions, versions...)
}

// NonNil returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) NonNil() Rule { return rule.WithPolicy(policyNonNilUUID) }

// NonMax returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) NonMax() Rule { return rule.WithPolicy(policyNonMaxUUID) }

// RFC9562VariantOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RFC9562VariantOnly() Rule { return rule.WithPolicy(policyRFCVariant) }

// WithoutPrerelease returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutPrerelease() Rule {
	return rule.WithPolicy(policySemVerPrerelease, "forbidden")
}

// RequirePrerelease returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RequirePrerelease() Rule { return rule.WithPolicy(policySemVerPrerelease, "required") }

// WithoutBuildMetadata returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutBuildMetadata() Rule { return rule.WithPolicy(policySemVerBuild, "forbidden") }

// RequireBuildMetadata returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RequireBuildMetadata() Rule { return rule.WithPolicy(policySemVerBuild, "required") }

// AtLeastVersion returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AtLeastVersion(value string) Rule { return rule.WithPolicy(policySemVerMin, value) }

// LessThanVersion returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) LessThanVersion(value string) Rule { return rule.WithPolicy(policySemVerMax, value) }

// BetweenVersions returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) BetweenVersions(minimum string, maximum string) Rule {
	return rule.WithPolicy(policySemVerMin, minimum).WithPolicy(policySemVerMax, maximum)
}

// AtLeastDecodedBytes returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AtLeastDecodedBytes(value int) Rule {
	return rule.WithPolicy(policyDecodedMin, strconv.Itoa(value))
}

// AtMostDecodedBytes returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AtMostDecodedBytes(value int) Rule {
	return rule.WithPolicy(policyDecodedMax, strconv.Itoa(value))
}

// ExactlyDecodedBytes returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) ExactlyDecodedBytes(value int) Rule {
	return rule.AtLeastDecodedBytes(value).AtMostDecodedBytes(value)
}

// WithHashPrefix returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithHashPrefix(value string) Rule { return rule.WithPolicy(policyHashPrefix, value) }

// DateOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) DateOnly() Rule { return rule.WithPolicy(policyDateOnly) }

// RequireOffset returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RequireOffset() Rule { return rule.WithPolicy(policyRequireOffset) }

// WithFractionalSeconds returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithFractionalSeconds() Rule {
	return rule.WithPolicy(policyFractionalSeconds, "required")
}

// WithoutFractionalSeconds returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutFractionalSeconds() Rule {
	return rule.WithPolicy(policyFractionalSeconds, "forbidden")
}

// Precision returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) Precision(value time.Duration) Rule {
	return rule.WithPolicy(policyTimePrecision, value.String())
}

// RequireSeconds returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RequireSeconds() Rule { return rule.WithPolicy(policyTimeSeconds) }

// BlockType returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) BlockType(value string) Rule { return rule.WithPolicy(policyPEMBlockTypes, value) }

// AllowedBlockTypes returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AllowedBlockTypes(values ...string) Rule {
	return rule.WithPolicy(policyPEMBlockTypes, values...)
}

// WithoutPEMHeaders returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutPEMHeaders() Rule { return rule.WithPolicy(policyPEMHeaders, "forbidden") }

// CurrentlyValid returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) CurrentlyValid() Rule { return rule.WithPolicy(policyValidAt, "now") }

// ValidAt returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) ValidAt(value time.Time) Rule {
	return rule.WithPolicy(policyValidAt, value.Format(time.RFC3339Nano))
}

// ValidForAtLeast returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) ValidForAtLeast(value time.Duration) Rule {
	return rule.WithPolicy(policyValidFor, value.String())
}

// ForHostname returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) ForHostname(value string) Rule {
	return rule.WithPolicy(policyCertificateHostname, value)
}

// CAOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) CAOnly() Rule { return rule.WithPolicy(policyCACertificate, "required") }

// LeafOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) LeafOnly() Rule { return rule.WithPolicy(policyCACertificate, "forbidden") }

// WithKeyAlgorithms returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithKeyAlgorithms(values ...string) Rule {
	return rule.WithPolicy(policyPrivateKeyAlgorithms, values...)
}

// RSAOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RSAOnly() Rule { return rule.WithKeyAlgorithms("RSA") }

// ECDSAOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) ECDSAOnly() Rule { return rule.WithKeyAlgorithms("ECDSA") }

// Ed25519Only returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) Ed25519Only() Rule { return rule.WithKeyAlgorithms("Ed25519") }

// AtLeastRSABits returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AtLeastRSABits(value int) Rule {
	return rule.WithPolicy(policyMinRSA, strconv.Itoa(value))
}

// PKCS8Only returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) PKCS8Only() Rule { return rule.WithPolicy(policyPKCS8) }

// ServerAuth returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) ServerAuth() Rule {
	return rule.withAdditionalPolicy(policyCertificateUsage, "server")
}

// ClientAuth returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) ClientAuth() Rule {
	return rule.withAdditionalPolicy(policyCertificateUsage, "client")
}

// RequireMediaTypeParameters returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RequireMediaTypeParameters() Rule {
	return rule.WithPolicy(policyMediaParameters, "required")
}

// WithoutMediaTypeParameters returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutMediaTypeParameters() Rule {
	return rule.WithPolicy(policyMediaParameters, "forbidden")
}

// AtLeastTime returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AtLeastTime(value time.Time) Rule {
	rule.MinDate = value.Format(time.RFC3339Nano)

	return rule
}

// AtMostTime returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AtMostTime(value time.Time) Rule {
	rule.MaxDate = value.Format(time.RFC3339Nano)

	return rule
}

func policy(rule Rule, name string) ([]string, bool) {
	values, exists := rule.Policies[name]

	return values, exists
}

func policyInt(rule Rule, name string) (int, bool) {
	values, exists := policy(rule, name)
	if !exists || len(values) != 1 {
		return 0, false
	}
	value, err := strconv.Atoi(values[0])
	if err != nil {
		return 0, false
	}

	return value, true
}

func validatePolicies(rule Rule, path string) error {
	for name, values := range rule.Policies {
		if name == "explicitInput" {
			if len(values) != 0 {
				return fmt.Errorf("envschema: explicitInput accepts no values")
			}
			continue
		}
		if name == "nonOverlapping" || name == "subnetsOf" {
			if (rule.Kind != KindList && rule.Kind != KindArray) || rule.Item == nil || rule.Item.Kind != KindCIDR {
				return fmt.Errorf("envschema: %s requires a CIDR collection", name)
			}
			if name == "nonOverlapping" && len(values) != 0 || name == "subnetsOf" && len(values) != 1 {
				return fmt.Errorf("envschema: invalid %s policy", name)
			}
			if name == "subnetsOf" {
				if _, err := netip.ParsePrefix(values[0]); err != nil {
					return err
				}
			}
			continue
		}
		if handled, err := validateExactPolicy(rule, name, values); handled {
			if err != nil {
				return fmt.Errorf("envschema: %s: %w", path, err)
			}
			continue
		}

		valid := false
		switch name {
		case policyContaining, policyNotContaining, policyUTF8, policyNoControl, policySingleLine, policyEqualFold:
			valid = rule.Kind == KindString || rule.Kind == KindSecret
		case policyBase:
			valid = rule.Kind == KindInt || rule.Kind == KindUInt || rule.Kind == KindBigInt
		case policyTrueValues, policyFalseValues:
			valid = rule.Kind == KindBoolean
		case policyAllowedKeys, policyRequiredKeys, policyJSONUniqueKeys:
			valid = rule.Kind == KindJSON || rule.Kind == KindMap
		case policyJSONDepth, policyJSONKind, policyJSONSize:
			valid = rule.Kind == KindJSON
		case policyCSV:
			valid = rule.Kind == KindList || rule.Kind == KindMap
		case policyRejectEmptyItems, policyCaseFoldUnique, policyDistinctMin, policySorted:
			valid = rule.Kind == KindList
		case policyRejectEmptyKeys, policyRejectEmptyValues:
			valid = rule.Kind == KindMap
		case policyCleanPath, policyExecutable, policyExtensions, policyGlob, policyLocalPath, policyNotExisting,
			policySymlink, policyWithin:
			valid = rule.Kind == KindPath || rule.Kind == KindUnixSocket
		case policyAllowRelative, policyCanonicalURI, policyOpaqueForbidden, policyPathPresence, policyPathPrefix, policyQueryKeys, policyRequireHost,
			policyURIHosts, policyUserPassword:
			valid = rule.Kind == KindURL || rule.Kind == KindURI
		case policyHostSuffix:
			valid = rule.Kind == KindURL || rule.Kind == KindURI || rule.Kind == KindHost
		case policyAllowIPAddress, policyAllowTrailingDot, policyLabelsMax, policyLabelsMin, policyRequireTrailingDot:
			valid = rule.Kind == KindHost
		case policyIPClass:
			valid = rule.Kind == KindIP || rule.Kind == KindEndpoint
		case policyCanonicalCIDR, policyContainedBy, policyContainsAddresses, policyPrefixBounds:
			valid = rule.Kind == KindCIDR
		case policyAllowEmptyHost, policyEndpointHostType, policyEndpointValidateHost, policyNonZeroPort, policyPortBounds:
			valid = rule.Kind == KindEndpoint
		case policyNonMaxUUID, policyNonNilUUID, policyRFCVariant, policyUUIDVersions:
			valid = rule.Kind == KindUUID
		case policySemVerBuild, policySemVerMax, policySemVerMin, policySemVerPrerelease:
			valid = rule.Kind == KindSemVer
		case policyDecodedMax, policyDecodedMin:
			valid = rule.Kind == KindBase64
		case policyHashPrefix:
			valid = rule.Kind == KindHash
		case policyDateOnly:
			valid = rule.Kind == KindDate
		case policyFractionalSeconds:
			valid = rule.Kind == KindTimestamp || rule.Kind == KindTimeOfDay
		case policyRequireOffset, policyTimePrecision:
			valid = rule.Kind == KindTimestamp
		case policyTimeSeconds:
			valid = rule.Kind == KindTimeOfDay
		case policyPEMBlockTypes, policyPEMHeaders:
			valid = rule.Kind == KindPEM || rule.Kind == KindCertificate || rule.Kind == KindCertBundle || rule.Kind == KindPublicKey || rule.Kind == KindPrivateKey
		case policyCACertificate, policyCertificateHostname, policyCertificateUsage, policyValidAt, policyValidFor:
			valid = rule.Kind == KindCertificate || rule.Kind == KindCertBundle
		case policyMinRSA, policyPrivateKeyAlgorithms:
			valid = rule.Kind == KindCertificate || rule.Kind == KindCertBundle || rule.Kind == KindPrivateKey || rule.Kind == KindPublicKey
		case policyPKCS8:
			valid = rule.Kind == KindPrivateKey
		case policyMediaParameters:
			valid = rule.Kind == KindMediaType
		}
		if !valid {
			return fmt.Errorf("envschema: %s uses unsupported policy %q on %s", path, name, rule.Kind)
		}
		if rule.Kind == KindList && (name == policyCaseFoldUnique || name == policyRejectEmptyItems) && !stringResultKind(rule.Item.Kind) {
			return fmt.Errorf("envschema: %s policy %q requires string list items", path, name)
		}
		if rule.Kind == KindList && name == policySorted && !orderedResultKind(rule.Item.Kind) {
			return fmt.Errorf("envschema: %s policy %q requires ordered list items", path, name)
		}
		minimum, maximum := policyCardinality(name)
		if len(values) < minimum || maximum >= 0 && len(values) > maximum {
			return fmt.Errorf("envschema: %s policy %q expects %s", path, name, policyCardinalityDescription(minimum, maximum))
		}
		for _, value := range values {
			if value == "" && name != policyEqualFold {
				return fmt.Errorf("envschema: %s policy %q has an empty value", path, name)
			}
		}
		if err := validatePolicyValues(name, values); err != nil {
			return fmt.Errorf("envschema: %s policy %q: %w", path, name, err)
		}
		if name == policyGlob && len(values) == 1 {
			if _, err := filepath.Match(values[0], ""); err != nil {
				return fmt.Errorf("envschema: %s has invalid glob policy: %w", path, err)
			}
		}
	}
	if trueValues, configured := policy(rule, policyTrueValues); configured {
		falseValues, falseConfigured := policy(rule, policyFalseValues)
		if falseConfigured {
			for _, trueValue := range trueValues {
				for _, falseValue := range falseValues {
					if strings.EqualFold(trueValue, falseValue) {
						return fmt.Errorf("envschema: %s boolean true and false values overlap at %q", path, trueValue)
					}
				}
			}
		}
	}
	for _, bounds := range [][2]string{
		{policyLabelsMin, policyLabelsMax},
		{policyDecodedMin, policyDecodedMax},
	} {
		minimum, hasMinimum := policyInt(rule, bounds[0])
		maximum, hasMaximum := policyInt(rule, bounds[1])
		if hasMinimum && hasMaximum && minimum > maximum {
			return fmt.Errorf("envschema: %s policy minimum exceeds maximum", path)
		}
	}
	if minimumValues, hasMinimum := policy(rule, policySemVerMin); hasMinimum {
		if maximumValues, hasMaximum := policy(rule, policySemVerMax); hasMaximum {
			minimum := semanticVersionBound(minimumValues[0])
			maximum := semanticVersionBound(maximumValues[0])
			if compareSemanticVersions(minimum, maximum) >= 0 {
				return fmt.Errorf("envschema: %s semantic version minimum must be less than maximum", path)
			}
		}
	}

	return nil
}

func stringResultKind(kind Kind) bool {
	switch kind {
	case KindString, KindEnum, KindPath, KindBase64, KindEmail, KindURL, KindHost, KindUUID, KindIP, KindHash,
		KindHex, KindSemVer, KindTimeZone, KindEndpoint, KindUnixSocket, KindTimeOfDay, KindURI, KindMediaType,
		KindULID, KindGlob:
		return true
	default:
		return false
	}
}

func orderedResultKind(kind Kind) bool {
	if stringResultKind(kind) {
		return true
	}
	switch kind {
	case KindNumber, KindFloat, KindInt, KindUInt, KindBytes, KindPort, KindDuration, KindDate, KindTimestamp,
		KindBigInt, KindDecimal, KindFileMode:
		return true
	default:
		return false
	}
}

func validatePolicyValues(name string, values []string) error {
	switch name {
	case policyBase:
		value, err := strconv.Atoi(values[0])
		if err != nil || value != 0 && (value < 2 || value > 36) {
			return fmt.Errorf("base must be 0 or between 2 and 36")
		}
	case policyJSONDepth, policyJSONSize, policyDistinctMin, policyLabelsMax, policyLabelsMin,
		policyDecodedMax, policyDecodedMin, policyMinRSA:
		value, err := strconv.Atoi(values[0])
		if err != nil || value < 0 {
			return fmt.Errorf("value must be a non-negative integer")
		}
	case policyPortBounds, policyPrefixBounds:
		minimum, minimumErr := strconv.Atoi(values[0])
		maximum, maximumErr := strconv.Atoi(values[1])
		if minimumErr != nil || maximumErr != nil || minimum < 0 || maximum < minimum {
			return fmt.Errorf("bounds must be ascending non-negative integers")
		}
		if name == policyPortBounds && maximum > 65535 || name == policyPrefixBounds && maximum > 128 {
			return fmt.Errorf("bounds exceed the supported range")
		}
	case policyIPClass:
		for _, value := range values {
			if !oneOf(value, "private", "public", "loopback", "notLoopback", "notUnspecified", "multicast", "notMulticast", "linkLocal", "notLinkLocal") {
				return fmt.Errorf("unsupported address class %q", value)
			}
		}
	case policyEndpointHostType:
		if !oneOf(values[0], "ip", "hostname") {
			return fmt.Errorf("unsupported endpoint host type %q", values[0])
		}
	case policyJSONKind:
		for _, value := range values {
			if !oneOf(value, "object", "array", "scalar", "nonNull") {
				return fmt.Errorf("unsupported JSON kind %q", value)
			}
		}
	case policyPathPresence, policyFractionalSeconds, policySemVerBuild, policySemVerPrerelease, policyCACertificate,
		policyMediaParameters:
		if !oneOf(values[0], "required", "forbidden") {
			return fmt.Errorf("value must be required or forbidden")
		}
	case policySorted:
		if !oneOf(values[0], "weak", "strict") {
			return fmt.Errorf("value must be weak or strict")
		}
	case policySymlink:
		if !oneOf(values[0], "required", "forbidden") {
			return fmt.Errorf("value must be required or forbidden")
		}
	case policyPEMHeaders:
		if values[0] != "forbidden" {
			return fmt.Errorf("value must be forbidden")
		}
	case policyCertificateUsage:
		for _, value := range values {
			if !oneOf(value, "server", "client") {
				return fmt.Errorf("unsupported certificate usage %q", value)
			}
		}
	case policyPrivateKeyAlgorithms:
		for _, value := range values {
			if !strings.EqualFold(value, "RSA") && !strings.EqualFold(value, "ECDSA") && !strings.EqualFold(value, "Ed25519") {
				return fmt.Errorf("unsupported key algorithm %q", value)
			}
		}
	case policyUUIDVersions:
		for _, value := range values {
			if !oneOf(value, "1", "2", "3", "4", "5", "6", "7", "8") {
				return fmt.Errorf("unsupported UUID version %q", value)
			}
		}
	case policyTimePrecision, policyValidFor:
		duration, err := time.ParseDuration(values[0])
		if err != nil || duration <= 0 {
			return fmt.Errorf("value must be a positive duration")
		}
	case policyValidAt:
		if values[0] != "now" {
			if _, err := time.Parse(time.RFC3339Nano, values[0]); err != nil {
				return fmt.Errorf("value must be now or an RFC 3339 timestamp")
			}
		}
	case policySemVerMin, policySemVerMax:
		version, valid := parseSemanticVersion(values[0])
		if !valid {
			return fmt.Errorf("value must be a semantic version")
		}
		parsedSemanticVersions.Store(values[0], version)
	case policyContainsAddresses:
		for _, value := range values {
			if _, err := netip.ParseAddr(value); err != nil {
				return fmt.Errorf("value %q must be an IP address", value)
			}
		}
	case policyContainedBy:
		if _, err := netip.ParsePrefix(values[0]); err != nil {
			return fmt.Errorf("value must be a CIDR prefix")
		}
	}

	return nil
}

func oneOf(value string, choices ...string) bool {
	return slices.Contains(choices, value)
}

func policyCardinality(name string) (int, int) {
	switch name {
	case policyUTF8, policyNoControl, policySingleLine, policyJSONUniqueKeys, policyCSV, policyRejectEmptyItems,
		policyCaseFoldUnique, policyCleanPath, policyExecutable, policyLocalPath, policyNotExisting, policyAllowRelative,
		policyCanonicalCIDR, policyCanonicalURI, policyOpaqueForbidden, policyRequireHost, policyUserPassword,
		policyAllowIPAddress, policyAllowTrailingDot, policyRequireTrailingDot, policyNonMaxUUID, policyNonNilUUID,
		policyRFCVariant, policyPKCS8, policyAllowEmptyHost, policyEndpointValidateHost, policyNonZeroPort,
		policyDateOnly, policyRequireOffset, policyTimeSeconds:
		return 0, 0
	case policyPortBounds, policyPrefixBounds:
		return 2, 2
	case policyContaining, policyNotContaining, policyTrueValues, policyFalseValues, policyAllowedKeys, policyRequiredKeys,
		policyExtensions, policyQueryKeys, policyURIHosts, policyContainsAddresses, policyUUIDVersions, policyPEMBlockTypes,
		policyPrivateKeyAlgorithms, policyCertificateUsage, policyIPClass, policyJSONKind:
		return 1, -1
	default:
		return 1, 1
	}
}

func policyCardinalityDescription(minimum int, maximum int) string {
	if maximum < 0 {
		return fmt.Sprintf("at least %d value(s)", minimum)
	}
	if minimum == maximum {
		return fmt.Sprintf("exactly %d value(s)", minimum)
	}

	return fmt.Sprintf("between %d and %d values", minimum, maximum)
}

// UniqueKeys explicitly requires distinct map keys after key normalization.
// Maps always reject duplicate keys, including without this modifier.
func (rule Rule) UniqueKeys() Rule {
	return rule.WithPolicy(policyJSONUniqueKeys)
}

// NonOverlapping rejects overlapping CIDR prefixes, including duplicates.
func (rule Rule) NonOverlapping() Rule {
	return rule.WithPolicy("nonOverlapping")
}

// SubnetsOf requires every CIDR prefix to lie within parent.
func (rule Rule) SubnetsOf(parent string) Rule {
	return rule.WithPolicy("subnetsOf", parent)
}

func checkCIDRCollection(rule Rule, value any, path string) error {
	_, overlap := policy(rule, "nonOverlapping")
	parents, within := policy(rule, "subnetsOf")
	if !overlap && !within {
		return nil
	}
	prefixes, ok := value.([]netip.Prefix)
	if !ok {
		return fmt.Errorf("[%s] expected CIDR collection", path)
	}
	var parent netip.Prefix
	if within {
		var err error
		parent, err = netip.ParsePrefix(parents[0])
		if err != nil {
			return err
		}
	}
	ordered := append([]netip.Prefix(nil), prefixes...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Masked().Addr().Less(ordered[j].Masked().Addr()) })
	for i, prefix := range ordered {
		if within && (prefix.Addr().BitLen() != parent.Addr().BitLen() || prefix.Bits() < parent.Bits() || !parent.Contains(prefix.Masked().Addr())) {
			return fmt.Errorf("[%s] subnet outside parent", path)
		}
		if overlap && i > 0 && ordered[i-1].Overlaps(prefix) {
			return fmt.Errorf("[%s] overlapping subnets", path)
		}
	}

	return nil
}

// ExplicitInput requires supplied non-empty text (or an allowed empty value).
// Defaults cannot satisfy this requirement; fallback names can.
func (rule Rule) ExplicitInput() Rule {
	return rule.WithPolicy("explicitInput")
}
