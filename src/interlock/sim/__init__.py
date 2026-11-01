"""Loopback stand-ins for systems a plan-bound substrate drives (1.3.0).

:mod:`interlock.sim.kubernetes` is a Kubernetes API server, with admission
webhooks, on 127.0.0.1; :mod:`interlock.sim.terraform` is a ``terraform``
command over a local model. Each speaks the real system's wire format, so
:class:`~interlock.kubernetes.KubernetesSubstrate` and
:class:`~interlock.terraform.TerraformSubstrate` run against them exactly as
against a cluster or the real CLI. They exist for tests and demos: CI, and
``fiduciary demo``, stage on Class P with no cloud credentials.
"""
