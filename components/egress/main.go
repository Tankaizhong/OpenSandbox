// Copyright 2026 Alibaba Group Holding Ltd.
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

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/alibaba/opensandbox/egress/pkg/dnsproxy"
	"github.com/alibaba/opensandbox/egress/pkg/iptables"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
)

// Linux MVP: DNS proxy + iptables REDIRECT. No nftables/full isolation yet.
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Start in allow-all mode; policy will be set via HTTP API.
	proxy, err := dnsproxy.New(nil, "")
	if err != nil {
		log.Fatalf("failed to init dns proxy: %v", err)
	}
	if err := proxy.Start(ctx); err != nil {
		log.Fatalf("failed to start dns proxy: %v", err)
	}
	log.Println("dns proxy started on 127.0.0.1:15353")

	if err := iptables.SetupRedirect(15353); err != nil {
		log.Fatalf("failed to install iptables redirect: %v", err)
	}
	log.Printf("iptables redirect configured (OUTPUT 53 -> 15353) with SO_MARK bypass for proxy upstream traffic")

	httpAddr := os.Getenv(policy.EgressServerAddrEnv)
	if httpAddr == "" {
		httpAddr = policy.DefaultEgressServerAddr
	}
	token := os.Getenv(policy.EgressAuthTokenEnv)
	if err := startPolicyServer(ctx, proxy, httpAddr, token); err != nil {
		log.Fatalf("failed to start policy server: %v", err)
	}
	if token == "" {
		log.Printf("policy server listening on %s (POST /policy); no token configured (%s)", httpAddr, policy.EgressAuthTokenEnv)
	} else {
		log.Printf("policy server listening on %s (POST /policy) with token auth", httpAddr)
	}

	<-ctx.Done()
	log.Println("received shutdown signal; exiting")
	_ = os.Stderr.Sync()
}
