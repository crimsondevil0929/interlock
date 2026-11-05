#!/usr/bin/env bash
# Prepare a Kubernetes cluster (kind) for tests/test_real_kubernetes.py and print
# the environment they read. Run as the cluster's admin:
#
#   kind create cluster --name interlock
#   eval "$(scripts/kind-setup.sh kind-interlock)"
#
# It creates the namespace interlock-test; a service account there that can
# edit it and nothing else (what the substrate acts as); and two admission
# policies, CEL, enforced by the API server itself:
#
# - interlock-x10 (MutatingAdmissionPolicy): a change of replicas on a
#   deployment labelled interlock.io/x10 is multiplied by ten, as a mutating
#   webhook would. The dry run measures the result.
# - interlock-ceiling (ValidatingAdmissionPolicy): at most 100 replicas.
set -euo pipefail

context="${1:?usage: kind-setup.sh <kubectl context>}"
k() { kubectl --context "$context" "$@"; }

k apply -f - >/dev/null <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: interlock-test
  labels:
    interlock.io/test: "true"
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: remediator
  namespace: interlock-test
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: remediator-edit
  namespace: interlock-test
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: edit
subjects:
  - kind: ServiceAccount
    name: remediator
    namespace: interlock-test
---
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: interlock-x10
spec:
  failurePolicy: Fail
  reinvocationPolicy: Never
  matchConstraints:
    namespaceSelector:
      matchLabels:
        interlock.io/test: "true"
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["UPDATE"]
        resources: ["deployments"]
  matchConditions:
    - name: labelled-and-rescaled
      expression: >-
        has(object.metadata.labels) && 'interlock.io/x10' in object.metadata.labels &&
        object.spec.replicas != oldObject.spec.replicas && object.spec.replicas % 10 != 0
  mutations:
    - patchType: ApplyConfiguration
      applyConfiguration:
        expression: "Object{spec: Object.spec{replicas: object.spec.replicas * 10}}"
---
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicyBinding
metadata:
  name: interlock-x10
spec:
  policyName: interlock-x10
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: interlock-ceiling
spec:
  failurePolicy: Fail
  matchConstraints:
    namespaceSelector:
      matchLabels:
        interlock.io/test: "true"
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["deployments"]
  validations:
    - expression: "object.spec.replicas <= 100"
      message: "at most 100 replicas in interlock-test"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: interlock-ceiling
spec:
  policyName: interlock-ceiling
  validationActions: ["Deny"]
EOF

server="$(k config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}')"
ca_file="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/interlock-kind-ca.crt"
k config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' \
  | base64 --decode > "$ca_file"
token="$(k -n interlock-test create token remediator --duration=2h)"

# Admission policies take effect within a second or two of their creation.
sleep 3

printf 'export INTERLOCK_TEST_K8S_SERVER=%q\n' "$server"
printf 'export INTERLOCK_TEST_K8S_CA=%q\n' "$ca_file"
printf 'export INTERLOCK_TEST_K8S_TOKEN=%q\n' "$token"
