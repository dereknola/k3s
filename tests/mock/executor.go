// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/daemons/executor/executor.go
//
// Generated by this command:
//
//	mockgen --source pkg/daemons/executor/executor.go -self_package github.com/k3s-io/k3s/tests/mock -package mock -mock_names Executor=Executor
//

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	http "net/http"
	reflect "reflect"

	cmds "github.com/k3s-io/k3s/pkg/cli/cmds"
	config "github.com/k3s-io/k3s/pkg/daemons/config"
	executor "github.com/k3s-io/k3s/pkg/daemons/executor"
	gomock "github.com/golang/mock/gomock"
	authenticator "k8s.io/apiserver/pkg/authentication/authenticator"
)

// Executor is a mock of Executor interface.
type Executor struct {
	ctrl     *gomock.Controller
	recorder *ExecutorMockRecorder
	isgomock struct{}
}

// ExecutorMockRecorder is the mock recorder for Executor.
type ExecutorMockRecorder struct {
	mock *Executor
}

// NewExecutor creates a new mock instance.
func NewExecutor(ctrl *gomock.Controller) *Executor {
	mock := &Executor{ctrl: ctrl}
	mock.recorder = &ExecutorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Executor) EXPECT() *ExecutorMockRecorder {
	return m.recorder
}

// APIServer mocks base method.
func (m *Executor) APIServer(ctx context.Context, args []string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "APIServer", ctx, args)
	ret0, _ := ret[0].(error)
	return ret0
}

// APIServer indicates an expected call of APIServer.
func (mr *ExecutorMockRecorder) APIServer(ctx, args any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "APIServer", reflect.TypeOf((*Executor)(nil).APIServer), ctx, args)
}

// APIServerHandlers mocks base method.
func (m *Executor) APIServerHandlers(ctx context.Context) (authenticator.Request, http.Handler, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "APIServerHandlers", ctx)
	ret0, _ := ret[0].(authenticator.Request)
	ret1, _ := ret[1].(http.Handler)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// APIServerHandlers indicates an expected call of APIServerHandlers.
func (mr *ExecutorMockRecorder) APIServerHandlers(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "APIServerHandlers", reflect.TypeOf((*Executor)(nil).APIServerHandlers), ctx)
}

// APIServerReadyChan mocks base method.
func (m *Executor) APIServerReadyChan() <-chan struct{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "APIServerReadyChan")
	ret0, _ := ret[0].(<-chan struct{})
	return ret0
}

// APIServerReadyChan indicates an expected call of APIServerReadyChan.
func (mr *ExecutorMockRecorder) APIServerReadyChan() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "APIServerReadyChan", reflect.TypeOf((*Executor)(nil).APIServerReadyChan))
}

// Bootstrap mocks base method.
func (m *Executor) Bootstrap(ctx context.Context, nodeConfig *config.Node, cfg cmds.Agent) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Bootstrap", ctx, nodeConfig, cfg)
	ret0, _ := ret[0].(error)
	return ret0
}

// Bootstrap indicates an expected call of Bootstrap.
func (mr *ExecutorMockRecorder) Bootstrap(ctx, nodeConfig, cfg any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Bootstrap", reflect.TypeOf((*Executor)(nil).Bootstrap), ctx, nodeConfig, cfg)
}

// CRI mocks base method.
func (m *Executor) CRI(ctx context.Context, node *config.Node) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CRI", ctx, node)
	ret0, _ := ret[0].(error)
	return ret0
}

// CRI indicates an expected call of CRI.
func (mr *ExecutorMockRecorder) CRI(ctx, node any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CRI", reflect.TypeOf((*Executor)(nil).CRI), ctx, node)
}

// CRIReadyChan mocks base method.
func (m *Executor) CRIReadyChan() <-chan struct{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CRIReadyChan")
	ret0, _ := ret[0].(<-chan struct{})
	return ret0
}

// CRIReadyChan indicates an expected call of CRIReadyChan.
func (mr *ExecutorMockRecorder) CRIReadyChan() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CRIReadyChan", reflect.TypeOf((*Executor)(nil).CRIReadyChan))
}

// CloudControllerManager mocks base method.
func (m *Executor) CloudControllerManager(ctx context.Context, ccmRBACReady <-chan struct{}, args []string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CloudControllerManager", ctx, ccmRBACReady, args)
	ret0, _ := ret[0].(error)
	return ret0
}

// CloudControllerManager indicates an expected call of CloudControllerManager.
func (mr *ExecutorMockRecorder) CloudControllerManager(ctx, ccmRBACReady, args any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CloudControllerManager", reflect.TypeOf((*Executor)(nil).CloudControllerManager), ctx, ccmRBACReady, args)
}

// Containerd mocks base method.
func (m *Executor) Containerd(ctx context.Context, node *config.Node) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Containerd", ctx, node)
	ret0, _ := ret[0].(error)
	return ret0
}

// Containerd indicates an expected call of Containerd.
func (mr *ExecutorMockRecorder) Containerd(ctx, node any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Containerd", reflect.TypeOf((*Executor)(nil).Containerd), ctx, node)
}

// ControllerManager mocks base method.
func (m *Executor) ControllerManager(ctx context.Context, args []string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ControllerManager", ctx, args)
	ret0, _ := ret[0].(error)
	return ret0
}

// ControllerManager indicates an expected call of ControllerManager.
func (mr *ExecutorMockRecorder) ControllerManager(ctx, args any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ControllerManager", reflect.TypeOf((*Executor)(nil).ControllerManager), ctx, args)
}

// CurrentETCDOptions mocks base method.
func (m *Executor) CurrentETCDOptions() (executor.InitialOptions, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CurrentETCDOptions")
	ret0, _ := ret[0].(executor.InitialOptions)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CurrentETCDOptions indicates an expected call of CurrentETCDOptions.
func (mr *ExecutorMockRecorder) CurrentETCDOptions() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CurrentETCDOptions", reflect.TypeOf((*Executor)(nil).CurrentETCDOptions))
}

// Docker mocks base method.
func (m *Executor) Docker(ctx context.Context, node *config.Node) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Docker", ctx, node)
	ret0, _ := ret[0].(error)
	return ret0
}

// Docker indicates an expected call of Docker.
func (mr *ExecutorMockRecorder) Docker(ctx, node any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Docker", reflect.TypeOf((*Executor)(nil).Docker), ctx, node)
}

// ETCD mocks base method.
func (m *Executor) ETCD(ctx context.Context, args *executor.ETCDConfig, extraArgs []string, test executor.TestFunc) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ETCD", ctx, args, extraArgs, test)
	ret0, _ := ret[0].(error)
	return ret0
}

// ETCD indicates an expected call of ETCD.
func (mr *ExecutorMockRecorder) ETCD(ctx, args, extraArgs, test any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ETCD", reflect.TypeOf((*Executor)(nil).ETCD), ctx, args, extraArgs, test)
}

// ETCDReadyChan mocks base method.
func (m *Executor) ETCDReadyChan() <-chan struct{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ETCDReadyChan")
	ret0, _ := ret[0].(<-chan struct{})
	return ret0
}

// ETCDReadyChan indicates an expected call of ETCDReadyChan.
func (mr *ExecutorMockRecorder) ETCDReadyChan() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ETCDReadyChan", reflect.TypeOf((*Executor)(nil).ETCDReadyChan))
}

// KubeProxy mocks base method.
func (m *Executor) KubeProxy(ctx context.Context, args []string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "KubeProxy", ctx, args)
	ret0, _ := ret[0].(error)
	return ret0
}

// KubeProxy indicates an expected call of KubeProxy.
func (mr *ExecutorMockRecorder) KubeProxy(ctx, args any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "KubeProxy", reflect.TypeOf((*Executor)(nil).KubeProxy), ctx, args)
}

// Kubelet mocks base method.
func (m *Executor) Kubelet(ctx context.Context, args []string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Kubelet", ctx, args)
	ret0, _ := ret[0].(error)
	return ret0
}

// Kubelet indicates an expected call of Kubelet.
func (mr *ExecutorMockRecorder) Kubelet(ctx, args any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Kubelet", reflect.TypeOf((*Executor)(nil).Kubelet), ctx, args)
}

// Scheduler mocks base method.
func (m *Executor) Scheduler(ctx context.Context, nodeReady <-chan struct{}, args []string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Scheduler", ctx, nodeReady, args)
	ret0, _ := ret[0].(error)
	return ret0
}

// Scheduler indicates an expected call of Scheduler.
func (mr *ExecutorMockRecorder) Scheduler(ctx, nodeReady, args any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Scheduler", reflect.TypeOf((*Executor)(nil).Scheduler), ctx, nodeReady, args)
}
