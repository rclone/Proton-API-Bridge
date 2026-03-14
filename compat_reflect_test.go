package proton_api_bridge

import (
	"errors"
	"reflect"
	"testing"
)

type noArgMethodTarget struct{}

func (noArgMethodTarget) Foo() {}

type panicMethodTarget struct{}

func (panicMethodTarget) Foo(string) {
	panic("boom")
}

type concreteErr string

func (e concreteErr) Error() string {
	return string(e)
}

func TestFindAndCallMethodHandlesNilTarget(t *testing.T) {
	results, called, err := findAndCallMethod(nil, "Foo")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if called {
		t.Fatalf("expected called=false")
	}
	if results != nil {
		t.Fatalf("expected nil results")
	}
}

func TestFindAndCallMethodHandlesIncompatibleArgCount(t *testing.T) {
	_, called, err := findAndCallMethod(noArgMethodTarget{}, "Foo", "arg")
	if !called {
		t.Fatalf("expected called=true")
	}
	if err == nil {
		t.Fatalf("expected error for incompatible signature")
	}
}

func TestFindAndCallMethodConvertsPanicToError(t *testing.T) {
	_, called, err := findAndCallMethod(panicMethodTarget{}, "Foo", "arg")
	if !called {
		t.Fatalf("expected called=true")
	}
	if err == nil {
		t.Fatalf("expected panic to be converted to error")
	}
}

func TestExtractErrorResultHandlesConcreteErrorKind(t *testing.T) {
	errValue := reflect.ValueOf(concreteErr("boom"))
	err, extractErr := extractErrorResult(errValue)
	if extractErr != nil {
		t.Fatalf("expected nil extract error, got %v", extractErr)
	}
	if !errors.Is(err, concreteErr("boom")) {
		t.Fatalf("expected concrete error, got %v", err)
	}
}
