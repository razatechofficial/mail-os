# Network policy

This implements contract §3 (`iam/docs/mailos-integration-contract.md`):
- only IAM's pods, and the MailOS console's BFF for console APIs, may reach MailOS over HTTP and gRPC
- the broker is reachable only by its producers and consumers

The manifests are in `deployments/networkpolicy/`, and `kubectl kustomize deployments/networkpolicy` renders them. Nothing in gitops was changed: the user changes gitops (see [What gitops must change](#what-gitops-must-change)).

**The CNI must enforce NetworkPolicy.** Calico and Cilium do. Flannel on its own and kind's default kindnet accept the objects but enforce nothing. Check with the test in [Verifying](#verifying) before relying on these rules.

## Labels the policies select

| Label | On | Meaning |
|---|---|---|
| `app.kubernetes.io/name: mailos` | every MailOS pod | the MailOS application |
| `app.kubernetes.io/component: server` | the server Deployment | HTTP 8080, gRPC 9090, metrics 9102 |
| `app.kubernetes.io/component: worker` | the worker Deployment | asynq workers, metrics 9102 |
| `app.kubernetes.io/component: migrate` | the migration Job | `mailos-migrate-postgres up` |
| `mailos.razatech.io/kafka-client: "true"` | only the Deployments that run the Kafka consumer (`FEATURE_PUBSUB_INGEST`) or the audit producer (`FEATURE_AUDIT_STREAM`) | may reach the broker |

A pod without the right labels gets nothing beyond the default deny. That is the safe failure: a mislabelled pod is cut off, not opened up.

## The rules

Every peer that depends on the cluster is marked `ADJUST` in its file.

| File | Policy | Allows | Why |
|---|---|---|---|
| `default-deny.yaml` | `mailos-default-deny` | nothing (all pods, ingress and egress) | Everything else is an explicit allow. Sync wave -1, so it exists before the pods |
| `dns.yaml` | `mailos-egress-dns` | egress UDP/TCP 53 to `kube-system` pods `k8s-app: kube-dns` | Name resolution for every other rule |
| `server-ingress.yaml` | `mailos-server-ingress-api` | ingress TCP 8080 and 9090 to the server from (a) namespace `iam`, pods `app.kubernetes.io/name: iam` and (b) namespace `mailos-client`, pods `app.kubernetes.io/name: mailos-client` | Contract §3. IAM's labels come from gitops `applications/iam` (its kustomization adds `app.kubernetes.io/name: iam` to every pod). The console values are placeholders until the console is in gitops. There is no ingress-controller peer: the API is not public |
| `metrics-ingress.yaml` | `mailos-ingress-metrics` | ingress TCP 9102 to the server and worker from namespace `observability` | Prometheus (gitops `infrastructure/observability`). The metrics listener is separate from the API, and the API rule never opens 9102 |
| `datastores-egress.yaml` | `mailos-egress-postgres` | egress TCP 5432 from the server, worker and migration Job to namespace `mailos-data`, pods `cnpg.io/cluster: mailos-pg` | The primary store. The data stores sit in their own namespace so this namespace's default deny never touches operator-managed pods. For a managed database, use an `ipBlock` of its endpoint instead |
| | `mailos-egress-redis` | egress TCP 6379 (and 26379 for Sentinel) from the server and worker to `mailos-data` pods `app.kubernetes.io/name: mailos-redis` | asynq queues, replay guards, rate limits. The migration Job does not use Redis |
| `iam-egress.yaml` | `mailos-egress-iam` | egress TCP 443 from the server and worker to `ingress-nginx` controller pods | `IAM_ISSUER` is IAM's public origin (`https://iam.averox.com`) behind ingress-nginx. Through it MailOS reads discovery and JWKS (token and message-signature checks) and, with Kafka OAUTHBEARER, the token endpoint. When the cluster sends that address straight to the controller pods, this rule matches. When the traffic leaves the cluster, the public-HTTPS rule below matches |
| `kafka-egress.yaml` | `mailos-egress-kafka` | egress TCP 9093 to `15.235.206.77/32`, only from pods labelled `mailos.razatech.io/kafka-client: "true"` | The broker is outside the cluster today (IAM's gitops sets `KAFKA_BROKERS=15.235.206.77:9092`). 9092 is plaintext, and MailOS refuses plaintext Kafka outside local and test (contract §2). So the rule names the broker's TLS + SASL listener, 9093; adjust it to the real port. For an in-cluster Strimzi broker, the file shows the selector to use instead |
| `providers-egress.yaml` | `mailos-egress-providers-worker` | egress from the worker to public addresses on TCP 25, 465, 587, 2525 (SMTP) and 443 (provider APIs, customer webhooks) | Sending mail |
| | `mailos-egress-https-server` | egress from the server to public addresses on TCP 443 | IAM's issuer when it is reached through the public address, and provider credential checks |

**What "public" means.** It is `0.0.0.0/0` except `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16` and `127.0.0.0/8`. Tenants configure provider hosts and webhook URLs, so this exclusion is also an SSRF backstop: the worker cannot be pointed at the cluster network or the cloud metadata service (`169.254.169.254`). It does not replace the application's own URL checks.

**When to narrow the server's rule.** If the server never dials providers itself (test sends go through the worker), remove the server's public-HTTPS rule once IAM's issuer is always reached through ingress-nginx.

**Not allowed, on purpose.** The following get no rule:
- the ingress controller to MailOS
- MailOS to IAM's pods directly
- MailOS to the Kubernetes API (the pods use no service account permissions)
- any egress from the migration Job other than Postgres and DNS

**If MailOS gains public endpoints.** Unsubscribe links, open and click tracking, or provider event webhooks would need public ingress. Add a separate policy for those paths' port, with the ingress-nginx peer, rather than widening `mailos-server-ingress-api`.

## The data namespace (`mailos-data`)

The namespace that holds Postgres and Redis must admit MailOS. A sample in the same style:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mailos-clients
  namespace: mailos-data
spec:
  podSelector:
    matchExpressions:
      - {key: cnpg.io/cluster, operator: In, values: [mailos-pg]}
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: mailos}}
          podSelector: {matchLabels: {app.kubernetes.io/name: mailos}}
      ports: [{protocol: TCP, port: 5432}]
```

Add the same for `app.kubernetes.io/name: mailos-redis` on 6379/26379. Keep the operator's own rules: CloudNativePG needs instance-to-instance 5432 and operator-to-instance 8000.

## Kafka: the broker side and the ACLs

### Who reaches the broker

`broker-sample/kafka-broker-ingress.yaml` is applied on the broker side, not by this folder. It is a sample for an in-cluster Strimzi cluster: only MailOS's labelled Kafka clients and IAM's pods reach the client listener (9093), plus the cluster's own brokers and the Strimzi operator. Strimzi can generate the same rule from the listener's `networkPolicyPeers`; use one or the other.

The broker today is the external host `15.235.206.77`, so the equivalent is a host firewall rule there. The client listener should accept only:
- the cluster's egress (NAT) addresses for the nodes that run MailOS and IAM
- no other address

The plaintext 9092 listener should be closed to everything but localhost once the clients have moved to TLS.

### Per-topic ACLs operators must set

Each service authenticates to the broker as its own principal (SASL SCRAM-SHA-512, or OAUTHBEARER with its IAM client credentials). Every message also carries IAM's message signature (contract §2), but ACLs are the first gate.

| Principal | Resource | Pattern | Operations |
|---|---|---|---|
| MailOS (`User:mailos`) | each IAM email topic in the template catalogue (`KAFKA_TOPICS`), for example `iam.auth.invite_requested` | literal | `Read`, `Describe` |
| MailOS | consumer group `mailos-events` (`KAFKA_GROUP_ID`) | literal | `Read` |
| MailOS | topic `mailos.audit.events` (`AUDIT_STREAM_TOPIC`) | literal | `Write`, `Describe` |
| MailOS | cluster | | `IdempotentWrite` (only if the producer is idempotent) |
| IAM (`User:iam`) | topics `iam.` | prefixed | `Write`, `Describe` |
| SIEM collector | topic `mailos.audit.events` and its own group | literal | `Read`, `Describe` |

**Grant MailOS literal topics, not the `iam.` prefix.** The task brief speaks of "read on `iam.*`", but IAM also uses `iam.public.spicedb_outbox`. That topic carries authorization relationships, and MailOS must not read it. Two ways to keep MailOS off it:
- grant MailOS each email topic literally (as in the table above)
- move IAM's email topics under a prefix of their own (for example `iam.email.`) and grant that prefix

IAM's own consumer of the outbox topic, group `iam-spicedb-worker`, keeps its existing ACLs.

**Nothing else.** No principal gets `Create`, `Delete`, `Alter` or `AlterConfigs` on topics. Topics are created by operators.

Strimzi expresses this as a `KafkaUser` with `authorization.type: simple`. On the external broker it is `kafka-acls.sh --add ... --resource-pattern-type literal|prefixed`.

## What gitops must change

The user makes these changes. None was made here.

1. **The MailOS application.** Add a MailOS application, for example `applications/mailos`, with namespace `mailos`:
   - The server and worker Deployments and the migration Job (a PreSync hook) carry the labels in the table above. Only the Kafka client Deployment carries `mailos.razatech.io/kafka-client: "true"`.
   - Its base includes these manifests, copied from or referencing `deployments/networkpolicy` at a pinned revision.
   - A ServiceMonitor that scrapes port 9102 (named, say, `metrics`). Do not scrape the HTTP port as IAM does today.
   - Pods run with `readOnlyRootFilesystem: true`, `runAsNonRoot: true` and `allowPrivilegeEscalation: false`, and drop all capabilities. The image (`deployments/Dockerfile`) needs no writable path.
2. **The data namespace.** Create `mailos-data` with the CloudNativePG cluster `mailos-pg` and the Redis deployment `mailos-redis`, plus the ingress policy above. If the names differ, adjust `datastores-egress.yaml`.
3. **The console.** When the MailOS console is deployed, set its namespace and pod labels in `server-ingress.yaml`. The placeholders are namespace `mailos-client` and `app.kubernetes.io/name: mailos-client`.
4. **IAM's side.**
   - IAM's MailOS URL and gRPC address point at the MailOS Service in namespace `mailos`, over TLS.
   - If the `iam` namespace ever gets a default deny, IAM needs egress to `mailos` on 8080 and 9090, and to the broker.
   - Keep IAM's pod label `app.kubernetes.io/name: iam`, which `server-ingress.yaml` selects on.
5. **Kafka.** Do this before `FEATURE_PUBSUB_INGEST` or `FEATURE_AUDIT_STREAM` is turned on:
   - Give the broker a TLS + SASL listener and set its port in `kafka-egress.yaml`.
   - Set the ACLs above and the host firewall.
   - Move IAM's `KAFKA_BROKERS` off the plaintext 9092 listener.
6. **Enforcement.** Confirm that the cluster's CNI enforces NetworkPolicy.

## Verifying

Run these after sync, from a throwaway pod:

```bash
# From an unrelated namespace: must time out.
kubectl run np-probe -n default --rm -it --image=curlimages/curl:8.10.1 --restart=Never -- \
  curl -m 5 -sS http://mailos.mailos.svc:8080/health
# From IAM's namespace with IAM's labels: must answer.
kubectl run np-probe -n iam --labels=app.kubernetes.io/name=iam --rm -it --image=curlimages/curl:8.10.1 --restart=Never -- \
  curl -m 5 -sS http://mailos.mailos.svc:8080/health
```

Use `https://` once the server serves TLS.
