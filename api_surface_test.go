package envschema_test

import (
	"testing"
	"time"

	"github.com/depthbomb/envschema"
)

func TestFluentAPISurface(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	stringRules := []envschema.Rule{
		envschema.String().Matching("x").WithMinLength(1).WithMaxLength(2).WithExactLength(1).CountRunes(),
		envschema.String().NonEmpty().PrintableOnly().WithoutSurroundingWhitespace().LowercaseOnly(),
		envschema.String().UppercaseOnly().Containing("x").NotContaining("y").ValidUTF8(),
		envschema.String().WithoutControlCharacters().SingleLine().EqualFold("X").WithByteLengthBetween(1, 2),
	}
	numericRules := []envschema.Rule{
		envschema.Number().AtMost(2).Between(1, 2).NonZero().NonNegative().NonPositive().NegativeOnly(),
		envschema.Int().StartingAt("1").EndingAt("2"),
	}
	collectionRules := []envschema.Rule{
		envschema.List(envschema.String()).SeparatedBy(";").PreserveWhitespace().AtMostItems(2),
		envschema.List(envschema.String()).CSV().RejectEmptyItems().AllowEmptyItems().CaseInsensitiveUniqueItems(),
		envschema.List(envschema.Int()).Sorted().StrictlySorted().AtLeastDistinctItems(1),
		envschema.Map(envschema.String(), envschema.Int()).KeyValueSeparatedBy(":").RejectEmptyKeys().RejectEmptyValues(),
	}
	pathRules := []envschema.Rule{
		envschema.Path().File().Existing().AbsoluteOnly().LocalOnly().Within(".").WithExtensions(".go"),
		envschema.Path().Directory().RelativeOnly().MatchingGlob("*").SymlinkForbidden().CleanOnly(),
		envschema.Path().NotExisting().Executable().SymlinkRequired(),
	}
	urlRules := []envschema.Rule{
		envschema.URL().HTTPOnly().RequireCredentials().WithoutPort().RequireQuery().RequireFragment(),
		envschema.URI().RequirePath().WithoutOpaqueForm().AllowRelativeReference().RequireQueryKeys("q"),
		envschema.URI().WithoutPath().WithPathPrefix("/v1").WithHostSuffix("example.com"),
	}
	hostRules := []envschema.Rule{
		envschema.Host().AllowTrailingDot().RequireTrailingDot().AtLeastLabels(2).AtMostLabels(3),
		envschema.Host().AllowIPAddress().WithDomainSuffix("example.com"),
	}
	ipRules := []envschema.Rule{
		envschema.IPAddress().PublicOnly().LoopbackOnly().WithoutLoopback().WithoutUnspecified(),
		envschema.IPAddress().MulticastOnly().WithoutMulticast().LinkLocalOnly().WithoutLinkLocal(),
		envschema.CIDR().PrefixLengthBetween(8, 24).ContainingAddresses("10.0.0.1").ContainedBy("10.0.0.0/8"),
		envschema.Endpoint().IPOnly().HostnameOnly().ValidateHostname().AllowEmptyHost(),
	}
	formatRules := []envschema.Rule{
		envschema.Base64().URLSafeEncoding().WithPadding(envschema.PaddingRequired).AtLeastDecodedBytes(1).AtMostDecodedBytes(3).ExactlyDecodedBytes(2),
		envschema.UUID().UUIDVersionIs(envschema.UUIDv7).NonMax(),
		envschema.SemVer().RequirePrerelease().WithoutBuildMetadata().RequireBuildMetadata().AtLeastVersion("1.0.0").LessThanVersion("2.0.0").BetweenVersions("1.0.0", "2.0.0"),
		envschema.Hash(envschema.SHA256).WithHashPrefix("sha256:"),
		envschema.Timestamp().DateOnly().WithFractionalSeconds().Precision(time.Millisecond).RequireSeconds().AtLeastTime(now).AtMostTime(now.Add(time.Hour)),
		envschema.PEM().BlockType("CERTIFICATE").WithoutPEMHeaders(),
		envschema.Certificate().ValidAt(now).ValidForAtLeast(time.Minute).CAOnly().ECDSAOnly().ClientAuth(),
		envschema.PrivateKey().Ed25519Only(),
	}

	all := [][]envschema.Rule{stringRules, numericRules, collectionRules, pathRules, urlRules, hostRules, ipRules, formatRules}
	count := 0
	for _, group := range all {
		count += len(group)
	}
	if count == 0 {
		t.Fatal("fluent API produced no rules")
	}
}

func TestConstructorsOptionsAndSchemaAliases(t *testing.T) {
	t.Parallel()

	constructors := []envschema.Rule{
		envschema.Number(), envschema.Path(), envschema.UnixSocket(), envschema.HTTPURL(),
		envschema.String(envschema.Pattern("x"), envschema.MinLength(1), envschema.MaxLength(2)),
		envschema.Int(envschema.Min(1), envschema.Max(2), envschema.Range(1, 2), envschema.Positive, envschema.Negative),
		envschema.Date(envschema.MinDate("2026-01-01"), envschema.MaxDate("2026-12-31")),
		envschema.List(envschema.String(), envschema.Separator(";"), envschema.PreserveListWhitespace, envschema.Unique),
		envschema.Path(envschema.PathType(envschema.PathFile), envschema.MustExist),
		envschema.Base64(envschema.URLSafe, envschema.Base64Padding(envschema.PaddingForbidden)),
		envschema.IPAddress(envschema.IP(envschema.IPv4)),
		envschema.UUID(envschema.UUIDVersioned(envschema.UUIDv4)),
		envschema.String(envschema.Optional, envschema.Default("value"), envschema.Trim),
	}
	if len(constructors) != 13 {
		t.Fatal("constructor smoke test is incomplete")
	}

	schema := envschema.Must(
		envschema.Named("A", "Alpha", envschema.Int().Optional()),
		envschema.Var("B", envschema.Int().Optional()),
	)
	_ = schema.MutuallyExclusive("A", "B")
	_ = schema.AtMostOneOf("A", "B")
	_ = schema.DifferentValues("A", "B")

	decoded := envschema.MustSchemaJSON(`{"variables":[{"name":"VALUE","rule":{"kind":"string"}}]}`)
	if len(decoded.Variables) != 1 {
		t.Fatal("MustSchemaJSON did not decode the schema")
	}
}
