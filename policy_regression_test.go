package envschema

import (
	"crypto/x509"
	"testing"
)

func TestIndependentPoliciesCompose(t *testing.T) {
	base := IPAddress().PrivateOnly()
	for _, rule := range []Rule{base.WithoutLoopback(), IPAddress().WithoutLoopback().PrivateOnly(), Endpoint().PrivateOnly().WithoutLoopback()} {
		if _, err := New(Var("VALUE", rule)); err != nil {
			t.Fatal(err)
		}
		public, private := "8.8.8.8", "10.0.0.1"
		if rule.Kind == KindEndpoint {
			public, private = public+":443", private+":443"
		}
		if _, err := parseRule(rule, public, "VALUE"); err == nil {
			t.Error("composed restrictions accepted public address")
		}
		if _, err := parseRule(rule, private, "VALUE"); err != nil {
			t.Fatal(err)
		}
	}
	if len(base.Policies[policyIPClass]) != 1 {
		t.Fatal("modifier mutated reusable base rule")
	}
	for _, rule := range []Rule{JSON().ScalarOnly().WithoutNull(), JSON().WithoutNull().ScalarOnly()} {
		for _, raw := range []string{"null", "[]", "{}"} {
			if _, err := parseRule(rule, raw, "VALUE"); err == nil {
				t.Errorf("composed scalar restriction accepted %s", raw)
			}
		}
		if _, err := parseRule(rule, "true", "VALUE"); err != nil {
			t.Fatal(err)
		}
	}
	certificate := &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if err := validateCertificatePolicies(Certificate().ServerAuth().ClientAuth(), certificate, "VALUE"); err == nil {
		t.Error("client-only certificate satisfied combined server and client usages")
	}
	for _, rule := range []Rule{IPAddress().WithPolicy(policyIPClass, "private", "invalid"), JSON().WithPolicy(policyJSONKind, "scalar", "invalid")} {
		if _, err := New(Var("VALUE", rule)); err == nil {
			t.Error("invalid second policy value passed validation")
		}
	}
}
