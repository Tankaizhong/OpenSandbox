# Copyright 2025 Alibaba Group Holding Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Unit tests for AgentSandboxService.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from src.api.schema import SandboxStatus
from src.config import (
    AppConfig,
    RuntimeConfig,
    ServerConfig,
    KubernetesRuntimeConfig,
    AgentSandboxRuntimeConfig,
)
from src.services.agent_sandbox import AgentSandboxService
from src.services.constants import SandboxErrorCodes


@pytest.fixture
def agent_sandbox_runtime_config():
    """Provide agent-sandbox runtime configuration"""
    return KubernetesRuntimeConfig(
        kubeconfig_path="/tmp/test-kubeconfig",
        namespace="test-namespace",
        service_account="test-sa",
        workload_provider="agent-sandbox",
    )


@pytest.fixture
def agent_sandbox_app_config(agent_sandbox_runtime_config):
    """Provide complete app configuration (agent-sandbox type)"""
    return AppConfig(
        server=ServerConfig(
            host="0.0.0.0",
            port=8080,
            log_level="DEBUG",
            api_key="test-api-key",
        ),
        runtime=RuntimeConfig(
            type="agent-sandbox",
            execd_image="ghcr.io/opensandbox/execd:test",
        ),
        kubernetes=agent_sandbox_runtime_config,
        agent_sandbox=AgentSandboxRuntimeConfig(
            template_file=None,
            execd_mode="init",
            shutdown_policy="Delete",
            ingress_enabled=True,
        ),
    )


@pytest.fixture
def app_config_docker():
    """Provide Docker type app configuration"""
    return AppConfig(
        server=ServerConfig(
            host="0.0.0.0",
            port=8080,
            log_level="DEBUG",
            api_key="test-api-key",
        ),
        runtime=RuntimeConfig(
            type="docker",
            execd_image="ghcr.io/opensandbox/execd:test",
        ),
        kubernetes=None,
    )


class TestAgentSandboxServiceInit:
    """AgentSandboxService initialization tests"""

    def test_init_with_valid_config_succeeds(self, agent_sandbox_runtime_config):
        """
        Test case: Successful initialization with valid config
        """
        config = AppConfig(
            server=ServerConfig(
                host="0.0.0.0",
                port=8080,
                log_level="DEBUG",
                api_key="test-api-key",
            ),
            runtime=RuntimeConfig(
                type="agent-sandbox",
                execd_image="ghcr.io/opensandbox/execd:test",
            ),
            kubernetes=agent_sandbox_runtime_config,
            agent_sandbox=AgentSandboxRuntimeConfig(
                template_file="/tmp/template.yaml",
                execd_mode="embedded",
                shutdown_policy="Retain",
                ingress_enabled=True,
            ),
        )

        with patch("src.services.agent_sandbox.K8sClient") as mock_k8s_client, patch(
            "src.services.agent_sandbox.AgentSandboxProvider"
        ) as mock_provider:
            mock_provider.return_value = MagicMock()

            service = AgentSandboxService(config)

            assert service.namespace == agent_sandbox_runtime_config.namespace
            assert service.execd_image == config.runtime.execd_image
            mock_k8s_client.assert_called_once_with(agent_sandbox_runtime_config)
            mock_provider.assert_called_once()
            call_kwargs = mock_provider.call_args.kwargs
            assert call_kwargs["template_file_path"] == "/tmp/template.yaml"
            assert call_kwargs["execd_mode"] == "embedded"
            assert call_kwargs["shutdown_policy"] == "Retain"
            assert call_kwargs["service_account"] == agent_sandbox_runtime_config.service_account

    def test_init_without_kubernetes_config_raises_error(self):
        """
        Test case: Raises exception when Kubernetes config is missing
        """
        config = AppConfig(
            server=ServerConfig(
                host="0.0.0.0",
                port=8080,
                log_level="DEBUG",
                api_key="test-api-key",
            ),
            runtime=RuntimeConfig(
                type="agent-sandbox",
                execd_image="ghcr.io/opensandbox/execd:test",
            ),
            kubernetes=None,
            agent_sandbox=AgentSandboxRuntimeConfig(),
        )

        with pytest.raises(HTTPException) as exc_info:
            AgentSandboxService(config)

        assert exc_info.value.status_code == 503
        assert exc_info.value.detail["code"] == SandboxErrorCodes.K8S_INITIALIZATION_ERROR

    def test_init_with_wrong_runtime_type_raises_error(self, app_config_docker):
        """
        Test case: Raises exception with wrong runtime type
        """
        with pytest.raises(ValueError, match="requires runtime.type = 'agent-sandbox'"):
            AgentSandboxService(app_config_docker)

    def test_init_with_k8s_client_failure_raises_http_exception(self, agent_sandbox_app_config):
        """
        Test case: Raises HTTPException when K8sClient initialization fails
        """
        with patch("src.services.agent_sandbox.K8sClient") as mock_k8s_client:
            mock_k8s_client.side_effect = Exception("Failed to load kubeconfig")

            with pytest.raises(HTTPException) as exc_info:
                AgentSandboxService(agent_sandbox_app_config)

            assert exc_info.value.status_code == 503
            assert "code" in exc_info.value.detail
            assert exc_info.value.detail["code"] == SandboxErrorCodes.K8S_INITIALIZATION_ERROR


class TestAgentSandboxServiceBuildSandbox:
    """AgentSandboxService _build_sandbox_from_workload tests"""

    def test_build_sandbox_from_workload_dict(self, agent_sandbox_app_config):
        """
        Test case: Verify sandbox fields are built from dict workload
        """
        with patch("src.services.agent_sandbox.K8sClient") as mock_k8s_client, patch(
            "src.services.agent_sandbox.AgentSandboxProvider"
        ) as mock_provider:
            mock_provider.return_value = MagicMock(
                get_expiration=MagicMock(return_value=datetime(2025, 12, 31, tzinfo=timezone.utc)),
                get_status=MagicMock(
                    return_value={
                        "state": "Running",
                        "reason": "Ready",
                        "message": "Ready",
                        "last_transition_at": datetime(2025, 12, 31, tzinfo=timezone.utc),
                    }
                ),
            )

            service = AgentSandboxService(agent_sandbox_app_config)

            workload = {
                "metadata": {
                    "labels": {
                        "opensandbox.io/id": "sandbox-id",
                        "team": "platform",
                    },
                    "creationTimestamp": "2025-12-31T09:00:00Z",
                },
                "spec": {
                    "podTemplate": {
                        "spec": {
                            "containers": [
                                {
                                    "image": "python:3.11",
                                    "command": ["/bin/bash"],
                                }
                            ]
                        }
                    }
                },
            }

            sandbox = service._build_sandbox_from_workload(workload)

            assert sandbox.id == "sandbox-id"
            assert sandbox.image.uri == "python:3.11"
            assert sandbox.entrypoint == ["/bin/bash"]
            assert sandbox.metadata == {"team": "platform"}
            assert isinstance(sandbox.status, SandboxStatus)
            assert sandbox.status.state == "Running"
