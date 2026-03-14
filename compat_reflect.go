package proton_api_bridge

import (
	"errors"
	"fmt"
	"reflect"
)

type methodCompatibilityError struct {
	err error
}

func (e *methodCompatibilityError) Error() string {
	return e.err.Error()
}

func (e *methodCompatibilityError) Unwrap() error {
	return e.err
}

func newMethodCompatibilityError(format string, args ...any) error {
	return &methodCompatibilityError{err: fmt.Errorf(format, args...)}
}

func isMethodCompatibilityError(err error) bool {
	var compatErr *methodCompatibilityError
	return errors.As(err, &compatErr)
}

func findAndCallMethod(target any, methodName string, args ...any) (_ []reflect.Value, called bool, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			called = true
			err = fmt.Errorf("%s panic: %v", methodName, recovered)
		}
	}()

	if target == nil {
		return nil, false, nil
	}

	targetValue := reflect.ValueOf(target)
	if !targetValue.IsValid() {
		return nil, false, nil
	}

	method := targetValue.MethodByName(methodName)
	if !method.IsValid() {
		return nil, false, nil
	}

	methodType := method.Type()
	if methodType.NumIn() != len(args) {
		return nil, true, newMethodCompatibilityError("%s has incompatible argument count", methodName)
	}

	callArgs := make([]reflect.Value, len(args))
	for i := range args {
		paramType := methodType.In(i)
		argValue, err := getCallableValue(paramType, args[i])
		if err != nil {
			return nil, true, newMethodCompatibilityError("%s argument %d: %w", methodName, i, err)
		}
		callArgs[i] = argValue
	}

	return method.Call(callArgs), true, nil
}

func getCallableValue(paramType reflect.Type, arg any) (reflect.Value, error) {
	if arg == nil {
		switch paramType.Kind() {
		case reflect.Interface, reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
			return reflect.Zero(paramType), nil
		default:
			return reflect.Value{}, fmt.Errorf("nil not assignable to %s", paramType)
		}
	}

	v := reflect.ValueOf(arg)
	if v.Type().AssignableTo(paramType) {
		return v, nil
	}
	if v.Type().ConvertibleTo(paramType) {
		return v.Convert(paramType), nil
	}

	return reflect.Value{}, fmt.Errorf("%s not assignable to %s", v.Type(), paramType)
}

func extractErrorResult(value reflect.Value) (error, error) {
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	if !value.Type().Implements(errorType) {
		return nil, fmt.Errorf("result does not implement error")
	}

	if isNilableKind(value.Kind()) && value.IsNil() {
		return nil, nil
	}

	err, ok := value.Interface().(error)
	if !ok {
		return nil, fmt.Errorf("result cannot be converted to error")
	}

	return err, nil
}

func isNilableKind(kind reflect.Kind) bool {
	switch kind {
	case reflect.Interface, reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return true
	default:
		return false
	}
}
