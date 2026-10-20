package captcha

import (
	"fmt"
	"sync"

	"github.com/dop251/goja"
)

// jsRuntime — goja VM-কে wrap করে captcha encrypt/decrypt দেয়।
// VM thread-safe নয়, তাই mutex দিয়ে সুরক্ষিত।
type jsRuntime struct {
	mu    sync.Mutex
	vm    *goja.Runtime
	encFn goja.Callable
	decFn goja.Callable
	alpha string
}

// newJSRuntime — snippet evaluate করে runtime বানায়
func newJSRuntime(snippet string) (*jsRuntime, error) {
	vm := goja.New()
	if _, err := vm.RunString(snippet); err != nil {
		return nil, fmt.Errorf("evaluate snippet: %w", err)
	}

	obj := vm.Get("__captcha")
	if obj == nil {
		return nil, fmt.Errorf("snippet did not define __captcha")
	}
	o := obj.ToObject(vm)
	if o == nil {
		return nil, fmt.Errorf("__captcha is not an object")
	}

	encVal := o.Get("encrypt")
	decVal := o.Get("decrypt")
	alphaVal := o.Get("alphabet")

	encFn, ok := goja.AssertFunction(encVal)
	if !ok {
		return nil, fmt.Errorf("__captcha.encrypt is not callable")
	}
	decFn, ok := goja.AssertFunction(decVal)
	if !ok {
		return nil, fmt.Errorf("__captcha.decrypt is not callable")
	}

	return &jsRuntime{
		vm:    vm,
		encFn: encFn,
		decFn: decFn,
		alpha: alphaVal.String(),
	}, nil
}

// encrypt — JS-এর encrypt function কল করে
//
//	js: G4(text, secret, startAt, length)
func (r *jsRuntime) encrypt(secret, text string, startAt, length int) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	res, err := r.encFn(
		goja.Undefined(),
		r.vm.ToValue(text),
		r.vm.ToValue(secret),
		r.vm.ToValue(startAt),
		r.vm.ToValue(length),
	)
	if err != nil {
		return "", fmt.Errorf("js encrypt: %w", err)
	}
	return res.String(), nil
}

// decrypt — JS-এর decrypt function কল করে
func (r *jsRuntime) decrypt(secret, text string, startAt, length int) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	res, err := r.decFn(
		goja.Undefined(),
		r.vm.ToValue(text),
		r.vm.ToValue(secret),
		r.vm.ToValue(startAt),
		r.vm.ToValue(length),
	)
	if err != nil {
		return "", fmt.Errorf("js decrypt: %w", err)
	}
	return res.String(), nil
}

// alphabet — JS-এর ব্যবহৃত alphabet string
func (r *jsRuntime) alphabetString() string {
	return r.alpha
}
