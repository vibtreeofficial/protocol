// Copyright 2023 VibTree Official
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build mage
// +build mage

package main

import (
	"context"
	"fmt"
	"go/build"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/vibtreeofficial/mageutil"
	"github.com/vibtreeofficial/protocol/psrpc"
)

var Default = Proto

func Bootstrap() error {
	return mageutil.Run(context.Background(),
		"go install github.com/twitchtv/twirp/protoc-gen-twirp@latest",
		"go install google.golang.org/protobuf/cmd/protoc-gen-go@latest",
		"go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest",
		"go install github.com/vibtreeofficial/psrpc/protoc-gen-psrpc@latest",
	)
}

// regenerate protobuf
func Proto() error {
	twirpProtoFiles := []string{
		"media_router_agent_dispatch.proto",
		"media_router_egress.proto",
		"media_router_ingress.proto",
		"media_router_room.proto",
		"media_router_sip.proto",
		"media_router_cloud_agent.proto",
	}
	protoFiles := []string{
		"media_router_agent.proto",
		"media_router_analytics.proto",
		"media_router_internal.proto",
		"media_router_models.proto",
		"media_router_rtc.proto",
		"media_router_webhook.proto",
		"media_router_metrics.proto",
	}
	grpcProtoFiles := []string{
		"infra/link.proto",
		"rpc/analytics.proto",
	}
	psrpcProtoFiles := []string{
		"rpc/agent.proto",
		"rpc/agent_dispatch.proto",
		"rpc/egress.proto",
		"rpc/ingress.proto",
		"rpc/io.proto",
		"rpc/keepalive.proto",
		"rpc/participant.proto",
		"rpc/room.proto",
		"rpc/roommanager.proto",
		"rpc/signal.proto",
		"rpc/whip_signal.proto",
		"rpc/sip.proto",
	}

	fmt.Println("generating protobuf")
	target := "media-router"
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}

	protoc, err := getToolPath("protoc")
	if err != nil {
		return err
	}
	protocGoPath, err := getToolPath("protoc-gen-go")
	if err != nil {
		return err
	}
	twirpPath, err := getToolPath("protoc-gen-twirp")
	if err != nil {
		return err
	}
	protocGrpcGoPath, err := getToolPath("protoc-gen-go-grpc")
	if err != nil {
		return err
	}

	fmt.Println("generating twirp protobuf")
	args := append([]string{
		"--go_out", target,
		"--twirp_out", target,
		"--go_opt=paths=source_relative",
		"--twirp_opt=paths=source_relative",
		"--plugin=go=" + protocGoPath,
		"--plugin=twirp=" + twirpPath,
		"-I=./protobufs",
	}, twirpProtoFiles...)
	cmd := exec.Command(protoc, args...)
	connectStd(cmd)
	if err := cmd.Run(); err != nil {
		return err
	}

	fmt.Println("generating replay twirp protobuf")
	replayTarget := "replay"
	args = append([]string{
		"--go_out", replayTarget,
		"--twirp_out", replayTarget,
		"--go_opt=paths=source_relative",
		"--twirp_opt=paths=source_relative",
		"--plugin=go=" + protocGoPath,
		"--plugin=twirp=" + twirpPath,
		"-I=./protobufs",
	}, "cloud_replay.proto")
	cmd = exec.Command(protoc, args...)
	connectStd(cmd)
	if err := cmd.Run(); err != nil {
		return err
	}

	fmt.Println("generating protobuf")
	args = append([]string{
		"--go_out", target,
		"--go_opt=paths=source_relative",
		"--plugin=go=" + protocGoPath,
		"-I=./protobufs",
	}, protoFiles...)
	cmd = exec.Command(protoc, args...)
	connectStd(cmd)
	if err := cmd.Run(); err != nil {
		return err
	}
	fmt.Println("generating grpc protobuf")
	args = append([]string{
		"--go_out", ".",
		"--go-grpc_out", ".",
		"--go_opt=paths=source_relative",
		"--go-grpc_opt=paths=source_relative",
		"--plugin=go=" + protocGoPath,
		"--plugin=go-grpc=" + protocGrpcGoPath,
		"-I=./protobufs",
	}, grpcProtoFiles...)
	cmd = exec.Command(protoc, args...)
	connectStd(cmd)
	if err := cmd.Run(); err != nil {
		return err
	}

	fmt.Println("generating psrpc protobuf")

	psrpcDir, err := mageutil.GetPkgDir("github.com/vibtreeofficial/psrpc")
	if err != nil {
		return err
	}
	psrpcPath, err := mageutil.GetToolPath("protoc-gen-psrpc")
	if err != nil {
		return err
	}
	if err := psrpc.CheckCompilerVersion(psrpcPath); err != nil {
		return err
	}

	args = append([]string{
		"--go_out", ".",
		"--psrpc_out", ".",
		"--go_opt=paths=source_relative",
		"--psrpc_opt=paths=source_relative",
		"--plugin=go=" + protocGoPath,
		"--plugin=psrpc=" + psrpcPath,
		"-I" + psrpcDir + "/protoc-gen-psrpc/options",
		"-I=./protobufs",
	}, psrpcProtoFiles...)
	cmd = exec.Command(protoc, args...)
	mageutil.ConnectStd(cmd)
	if err = cmd.Run(); err != nil {
		return err
	}

	return nil
}

// run tests
func Test() error {
	cmd := exec.Command("go", "test", "-race", "./...")
	connectStd(cmd)
	return cmd.Run()
}

// helpers

func getToolPath(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	// check under gopath
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = build.Default.GOPATH
	}
	p := filepath.Join(gopath, "bin", name)
	if _, err := os.Stat(p); err != nil {
		return "", err
	}
	return p, nil
}

func connectStd(cmd *exec.Cmd) {
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
}
