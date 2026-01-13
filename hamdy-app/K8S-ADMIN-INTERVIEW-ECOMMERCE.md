# Kubernetes Administrator Interview Preparation
## E-Commerce & Payment Systems Focus

---

## Table of Contents

1. [SSL/TLS Certificates](#1-ssltls-certificates)
2. [Ingress & Traffic Management](#2-ingress--traffic-management)
3. [Security Best Practices](#3-security-best-practices)
4. [High Availability & Scalability](#4-high-availability--scalability)
5. [Secrets Management](#5-secrets-management)
6. [PCI-DSS Compliance](#6-pci-dss-compliance)
7. [Monitoring & Logging](#7-monitoring--logging)
8. [Disaster Recovery](#8-disaster-recovery)
9. [Common Interview Questions](#9-common-interview-questions)
10. [Hands-On Scenarios](#10-hands-on-scenarios)

---

## 1. SSL/TLS Certificates

### 1.1 What is SSL/TLS?

- **SSL (Secure Sockets Layer)** / **TLS (Transport Layer Security)** encrypts data between client and server
- TLS is the modern, more secure version (TLS 1.2, 1.3)
- Essential for e-commerce to protect payment data

### 1.2 Certificate Types

| Type | Description | Use Case |
|------|-------------|----------|
| **DV (Domain Validation)** | Validates domain ownership only | Basic websites |
| **OV (Organization Validation)** | Validates organization identity | Business websites |
| **EV (Extended Validation)** | Strictest validation, green bar | E-commerce, Banking |
| **Wildcard** | Covers *.domain.com | Multiple subdomains |
| **SAN/Multi-domain** | Multiple domains in one cert | Multiple sites |

### 1.3 SSL in Kubernetes - Methods

#### Method 1: TLS Termination at Ingress (Most Common)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ecommerce-ingress
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
    - hosts:
        - shop.example.com
        - api.example.com
      secretName: ecommerce-tls-secret
  rules:
    - host: shop.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: frontend-service
                port:
                  number: 80
```

#### Method 2: Create TLS Secret Manually

```bash
# Create secret from certificate files
kubectl create secret tls ecommerce-tls-secret \
  --cert=fullchain.pem \
  --key=privkey.pem \
  -n production
```

```yaml
# Or declaratively
apiVersion: v1
kind: Secret
metadata:
  name: ecommerce-tls-secret
  namespace: production
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-certificate>
  tls.key: <base64-encoded-private-key>
```

#### Method 3: Cert-Manager (Automated - Recommended)

```yaml
# Install cert-manager
# kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# ClusterIssuer for Let's Encrypt
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod-key
    solvers:
      - http01:
          ingress:
            class: nginx

---
# Certificate resource
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ecommerce-cert
  namespace: production
spec:
  secretName: ecommerce-tls-secret
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  commonName: shop.example.com
  dnsNames:
    - shop.example.com
    - api.example.com
    - payments.example.com
```

### 1.4 SSL Interview Questions

**Q: How do you handle SSL certificate renewal in Kubernetes?**
```
A: Use cert-manager with Let's Encrypt for automatic renewal.
   Cert-manager monitors certificate expiry and renews 30 days before expiration.
   For manual certs, set up monitoring alerts for expiry and update secrets.
```

**Q: What happens when an SSL certificate expires?**
```
A: - Browsers show security warning
   - HTTPS connections fail
   - Payment gateways reject connections
   - API calls fail with SSL errors
   - Customer trust is lost
```

**Q: How do you check certificate expiry?**
```bash
# Check certificate in secret
kubectl get secret ecommerce-tls-secret -o jsonpath='{.data.tls\.crt}' | \
  base64 -d | openssl x509 -noout -dates

# Check live certificate
echo | openssl s_client -connect shop.example.com:443 2>/dev/null | \
  openssl x509 -noout -dates

# Using cert-manager
kubectl get certificates -A
```

**Q: Difference between TLS termination and TLS passthrough?**
```
TLS Termination:
- SSL decrypted at Ingress/Load Balancer
- Backend receives plain HTTP
- Easier to manage, inspect traffic
- Certificate managed at ingress level

TLS Passthrough:
- SSL passed directly to backend pod
- End-to-end encryption
- Backend manages its own certificate
- Required for some compliance (PCI-DSS)
- Configure with: nginx.ingress.kubernetes.io/ssl-passthrough: "true"
```

---

## 2. Ingress & Traffic Management

### 2.1 Ingress Controller Types

| Controller | Best For |
|------------|----------|
| **NGINX Ingress** | General purpose, most common |
| **AWS ALB Ingress** | AWS native, Layer 7 |
| **Traefik** | Dynamic configuration, Let's Encrypt |
| **Istio Gateway** | Service mesh, advanced routing |
| **HAProxy** | High performance |

### 2.2 E-Commerce Ingress Example

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ecommerce-ingress
  annotations:
    # SSL
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"

    # Rate limiting (protect against DDoS)
    nginx.ingress.kubernetes.io/limit-rps: "100"
    nginx.ingress.kubernetes.io/limit-connections: "50"

    # Security headers
    nginx.ingress.kubernetes.io/configuration-snippet: |
      add_header X-Frame-Options "SAMEORIGIN" always;
      add_header X-Content-Type-Options "nosniff" always;
      add_header X-XSS-Protection "1; mode=block" always;
      add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Timeouts for payment processing
    nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "300"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - shop.example.com
        - api.example.com
      secretName: ecommerce-tls-secret
  rules:
    - host: shop.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: frontend
                port:
                  number: 80
          - path: /api
            pathType: Prefix
            backend:
              service:
                name: api-gateway
                port:
                  number: 8080
          - path: /payments
            pathType: Prefix
            backend:
              service:
                name: payment-service
                port:
                  number: 443
```

---

## 3. Security Best Practices

### 3.1 Network Policies

```yaml
# Isolate payment service - only allow from API gateway
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payment-service-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: payment-service
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: api-gateway
      ports:
        - protocol: TCP
          port: 8443
  egress:
    # Allow connection to payment gateway (Stripe, PayPal)
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - protocol: TCP
          port: 443
    # Allow DNS
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
```

### 3.2 Pod Security Standards

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: payment-service
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: payment
      image: payment-service:v1.0
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      resources:
        limits:
          memory: "512Mi"
          cpu: "500m"
        requests:
          memory: "256Mi"
          cpu: "250m"
```

### 3.3 RBAC for E-Commerce

```yaml
# Limited access for developers
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: developer-role
  namespace: staging
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
  # NO access to secrets (payment credentials)

---
# Strict access for payment namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: payment-admin
  namespace: payment
rules:
  - apiGroups: [""]
    resources: ["*"]
    verbs: ["*"]
```

---

## 4. High Availability & Scalability

### 4.1 HPA for E-Commerce Services

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: frontend-hpa
  namespace: production
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: frontend
  minReplicas: 3
  maxReplicas: 50
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 30
      policies:
        - type: Percent
          value: 100
          periodSeconds: 15
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 10
          periodSeconds: 60
```

### 4.2 Pod Disruption Budget

```yaml
# Ensure payment service always has minimum replicas
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: payment-pdb
  namespace: production
spec:
  minAvailable: 2  # Or use maxUnavailable: 1
  selector:
    matchLabels:
      app: payment-service
```

### 4.3 Anti-Affinity for HA

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-service
spec:
  replicas: 3
  template:
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchLabels:
                  app: payment-service
              topologyKey: kubernetes.io/hostname
        # Spread across availability zones
        topologySpreadConstraints:
          - maxSkew: 1
            topologyKey: topology.kubernetes.io/zone
            whenUnsatisfiable: DoNotSchedule
            labelSelector:
              matchLabels:
                app: payment-service
```

---

## 5. Secrets Management

### 5.1 Kubernetes Secrets (Basic)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: payment-gateway-credentials
  namespace: production
type: Opaque
stringData:
  STRIPE_API_KEY: "sk_live_xxxxxxxxxxxx"
  STRIPE_WEBHOOK_SECRET: "whsec_xxxxxxxxxxxx"
  DATABASE_PASSWORD: "secure-password"
```

### 5.2 External Secrets Operator (Recommended)

```yaml
# ExternalSecret syncs from AWS Secrets Manager
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: payment-secrets
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    kind: ClusterSecretStore
    name: aws-secrets-manager
  target:
    name: payment-gateway-credentials
    creationPolicy: Owner
  data:
    - secretKey: STRIPE_API_KEY
      remoteRef:
        key: production/payment/stripe
        property: api_key
    - secretKey: DATABASE_PASSWORD
      remoteRef:
        key: production/payment/database
        property: password
```

### 5.3 Sealed Secrets (GitOps)

```bash
# Encrypt secret for Git storage
kubeseal --format yaml < secret.yaml > sealed-secret.yaml
```

```yaml
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: payment-credentials
  namespace: production
spec:
  encryptedData:
    STRIPE_API_KEY: AgBy8hCi...encrypted...
```

---

## 6. PCI-DSS Compliance

### 6.1 Key Requirements for Kubernetes

| Requirement | Kubernetes Implementation |
|-------------|---------------------------|
| **Encrypt data in transit** | TLS at ingress, mTLS between services |
| **Encrypt data at rest** | etcd encryption, encrypted PVs |
| **Access control** | RBAC, Network Policies |
| **Audit logging** | API server audit logs |
| **Vulnerability scanning** | Trivy, image scanning |
| **Network segmentation** | Namespaces, Network Policies |

### 6.2 Encryption at Rest

```yaml
# /etc/kubernetes/encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-32-byte-key>
      - identity: {}
```

### 6.3 Audit Logging

```yaml
# audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all requests to secrets
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets"]
  # Log all requests in payment namespace
  - level: RequestResponse
    namespaces: ["payment"]
  # Don't log read-only requests to certain resources
  - level: None
    resources:
      - group: ""
        resources: ["configmaps"]
    verbs: ["get", "list", "watch"]
```

---

## 7. Monitoring & Logging

### 7.1 Key Metrics for E-Commerce

```yaml
# PrometheusRule for e-commerce alerts
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: ecommerce-alerts
spec:
  groups:
    - name: payment.rules
      rules:
        # High payment failure rate
        - alert: HighPaymentFailureRate
          expr: |
            sum(rate(payment_transactions_total{status="failed"}[5m])) /
            sum(rate(payment_transactions_total[5m])) > 0.05
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "Payment failure rate above 5%"

        # Payment service down
        - alert: PaymentServiceDown
          expr: up{job="payment-service"} == 0
          for: 1m
          labels:
            severity: critical

        # High latency on checkout
        - alert: CheckoutHighLatency
          expr: |
            histogram_quantile(0.95,
              rate(http_request_duration_seconds_bucket{path="/checkout"}[5m])
            ) > 3
          for: 5m
          labels:
            severity: warning

        # SSL certificate expiring
        - alert: SSLCertificateExpiringSoon
          expr: |
            (cert_manager_certificate_expiration_timestamp_seconds - time())
            < 7 * 24 * 3600
          for: 1h
          labels:
            severity: warning
          annotations:
            summary: "SSL certificate expires in less than 7 days"
```

### 7.2 Logging Stack

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Pods      │────►│  Fluentd/   │────►│   Elastic   │
│  (stdout)   │     │  Fluent Bit │     │   Search    │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                                               ▼
                                        ┌─────────────┐
                                        │   Kibana    │
                                        └─────────────┘
```

---

## 8. Disaster Recovery

### 8.1 Backup Strategy

```bash
# Backup etcd
ETCDCTL_API=3 etcdctl snapshot save backup.db \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key

# Backup using Velero
velero backup create ecommerce-backup \
  --include-namespaces production,payment \
  --include-resources deployments,services,secrets,configmaps,pvc
```

### 8.2 Multi-Region Setup

```
                    ┌─────────────────┐
                    │   Global LB     │
                    │  (Route53/CF)   │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │ Region A │  │ Region B │  │ Region C │
        │  (Primary)│  │ (Standby)│  │  (DR)    │
        │   K8s    │  │   K8s    │  │   K8s    │
        └──────────┘  └──────────┘  └──────────┘
```

---

## 9. Common Interview Questions

### Kubernetes Basics

**Q: What happens when a pod is created?**
```
1. kubectl sends request to API Server
2. API Server authenticates and validates
3. API Server stores pod spec in etcd
4. Scheduler assigns pod to node
5. Kubelet on node pulls image
6. Kubelet creates container via CRI
7. Pod status updated in etcd
```

**Q: Difference between Deployment, StatefulSet, DaemonSet?**
```
Deployment:
- Stateless applications
- Random pod names (frontend-abc123)
- Any pod can be replaced
- Use for: web servers, APIs

StatefulSet:
- Stateful applications
- Ordered pod names (mysql-0, mysql-1)
- Stable network identity
- Persistent storage per pod
- Use for: databases, Kafka, Redis

DaemonSet:
- One pod per node
- Use for: log collectors, monitoring agents, CNI plugins
```

**Q: How does Kubernetes service discovery work?**
```
1. CoreDNS runs as a service in cluster
2. Each service gets DNS record: <service>.<namespace>.svc.cluster.local
3. Pods use CoreDNS for resolution
4. Service IP is virtual, handled by kube-proxy
5. kube-proxy uses iptables/IPVS to route to pod IPs
```

### Security Questions

**Q: How do you secure sensitive data like payment credentials?**
```
1. Use Kubernetes Secrets (base64, not encrypted by default)
2. Enable etcd encryption at rest
3. Use External Secrets Operator with AWS Secrets Manager/Vault
4. Implement RBAC to restrict secret access
5. Use Network Policies to limit which pods can access payment services
6. Never log secrets, use environment variables not files when possible
7. Rotate credentials regularly
```

**Q: How do you implement zero-trust security in Kubernetes?**
```
1. mTLS between all services (Istio/Linkerd)
2. Network Policies - deny all by default
3. Pod Security Standards - restricted mode
4. RBAC - least privilege principle
5. Image scanning and admission control
6. Runtime security (Falco)
7. Audit logging
```

### Troubleshooting

**Q: Payment service is slow. How do you troubleshoot?**
```
1. Check pod resource usage:
   kubectl top pods -n production

2. Check for OOM kills:
   kubectl describe pod <pod> | grep -i oom

3. Check HPA status:
   kubectl get hpa

4. Check network latency:
   kubectl exec -it <pod> -- curl -w "@curl-format.txt" payment-gateway.com

5. Check database connections:
   kubectl logs <pod> | grep -i connection

6. Check for CPU throttling:
   kubectl exec -it <pod> -- cat /sys/fs/cgroup/cpu/cpu.stat

7. Review Prometheus metrics for latency spikes
```

**Q: SSL certificate not working. How do you debug?**
```bash
# 1. Check certificate in secret
kubectl get secret tls-secret -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -text -noout

# 2. Check cert-manager certificate status
kubectl describe certificate <cert-name>

# 3. Check cert-manager logs
kubectl logs -n cert-manager deploy/cert-manager

# 4. Check ingress events
kubectl describe ingress <ingress-name>

# 5. Test SSL externally
openssl s_client -connect shop.example.com:443 -servername shop.example.com

# 6. Check if secret is mounted correctly
kubectl exec -it <ingress-pod> -- ls /etc/nginx/ssl/
```

---

## 10. Hands-On Scenarios

### Scenario 1: Deploy Payment Service with SSL

```bash
# 1. Create namespace
kubectl create namespace payment

# 2. Create TLS secret
kubectl create secret tls payment-tls \
  --cert=cert.pem --key=key.pem -n payment

# 3. Deploy application
kubectl apply -f payment-deployment.yaml

# 4. Create service
kubectl apply -f payment-service.yaml

# 5. Create ingress with TLS
kubectl apply -f payment-ingress.yaml

# 6. Verify
curl -v https://payments.example.com/health
```

### Scenario 2: Scale During Flash Sale

```bash
# 1. Pre-scale before sale
kubectl scale deployment frontend --replicas=20
kubectl scale deployment cart-service --replicas=15
kubectl scale deployment payment-service --replicas=10

# 2. Adjust HPA limits
kubectl patch hpa frontend-hpa -p '{"spec":{"maxReplicas":100}}'

# 3. Monitor during sale
watch kubectl top pods
watch kubectl get hpa

# 4. Scale down after sale
kubectl scale deployment frontend --replicas=5
```

### Scenario 3: Certificate Renewal Failed

```bash
# 1. Check certificate status
kubectl get certificates -A
kubectl describe certificate ecommerce-cert

# 2. Check cert-manager logs
kubectl logs -n cert-manager deploy/cert-manager --tail=100

# 3. Check ACME challenges
kubectl get challenges -A
kubectl describe challenge <challenge-name>

# 4. Force renewal
kubectl delete certificate ecommerce-cert
kubectl apply -f certificate.yaml

# 5. Verify new certificate
kubectl get secret ecommerce-tls -o jsonpath='{.data.tls\.crt}' | \
  base64 -d | openssl x509 -noout -dates
```

---

## Quick Reference Commands

```bash
# SSL/TLS
kubectl get certificates -A
kubectl describe certificate <name>
kubectl get secret <tls-secret> -o yaml

# Ingress
kubectl get ingress -A
kubectl describe ingress <name>
kubectl logs -n ingress-nginx deploy/ingress-nginx-controller

# Scaling
kubectl get hpa
kubectl top pods
kubectl top nodes

# Security
kubectl get networkpolicies -A
kubectl auth can-i --list --as=system:serviceaccount:default:mysa
kubectl get psp (deprecated, use Pod Security Standards)

# Troubleshooting
kubectl get events --sort-by='.lastTimestamp'
kubectl logs <pod> --previous
kubectl exec -it <pod> -- /bin/sh
```

---

## 11. Practice Scenarios (Interview Simulations)

### Scenario 4: Production Database Connection Issues

**Situation:** Payment service cannot connect to the database. Orders are failing.

**Your troubleshooting steps:**

```bash
# Step 1: Check pod status and logs
kubectl get pods -n production -l app=payment-service
kubectl logs -n production deployment/payment-service --tail=100 | grep -i database

# Step 2: Check if database pods are running
kubectl get pods -n production -l app=postgres
kubectl describe pod postgres-0 -n production

# Step 3: Check service endpoints
kubectl get endpoints postgres-service -n production
# If endpoints are empty, no healthy pods are backing the service

# Step 4: Check network connectivity from payment pod
kubectl exec -it payment-service-xxx -n production -- nc -zv postgres-service 5432

# Step 5: Check Network Policies blocking traffic
kubectl get networkpolicies -n production
kubectl describe networkpolicy postgres-network-policy -n production

# Step 6: Check database credentials secret
kubectl get secret db-credentials -n production -o yaml
# Verify the secret is mounted correctly in the pod

# Step 7: Check resource limits (database might be OOM killed)
kubectl describe pod postgres-0 -n production | grep -A5 "Last State"

# Step 8: Check PVC status (storage issues)
kubectl get pvc -n production
kubectl describe pvc postgres-data -n production
```

**Expected Answer Points:**
- Check pod logs first
- Verify service endpoints exist
- Test network connectivity
- Check Network Policies
- Verify credentials
- Check for OOM kills
- Verify storage is healthy

---

### Scenario 5: SSL Certificate Expired in Production

**Situation:** Customers report "Your connection is not secure" error on the website.

**Immediate actions:**

```bash
# Step 1: Verify the certificate has expired
echo | openssl s_client -connect shop.example.com:443 2>/dev/null | \
  openssl x509 -noout -dates
# Output shows: notAfter=Jan 10 00:00:00 2024 GMT (expired)

# Step 2: Check cert-manager certificate status
kubectl get certificates -n production
kubectl describe certificate ecommerce-cert -n production
# Look for: Status: False, Reason: Expired

# Step 3: Check why renewal failed
kubectl logs -n cert-manager deployment/cert-manager --tail=200

# Step 4: Check ACME challenges (for Let's Encrypt)
kubectl get challenges -A
kubectl describe challenge <challenge-name>
# Common issues: DNS not resolving, HTTP challenge path blocked

# Step 5: Emergency fix - Manually create certificate
# If you have backup certificates:
kubectl create secret tls ecommerce-tls-secret \
  --cert=backup-cert.pem \
  --key=backup-key.pem \
  -n production \
  --dry-run=client -o yaml | kubectl apply -f -

# Step 6: Force cert-manager to re-issue
kubectl delete certificate ecommerce-cert -n production
kubectl apply -f certificate.yaml

# Step 7: Verify new certificate is issued
kubectl get certificates -n production -w
# Wait for READY=True

# Step 8: Verify ingress is using new certificate
kubectl describe ingress ecommerce-ingress -n production
curl -v https://shop.example.com 2>&1 | grep "expire date"
```

**Prevention:**
```yaml
# PrometheusRule to alert before expiry
- alert: SSLCertificateExpiringSoon
  expr: (cert_manager_certificate_expiration_timestamp_seconds - time()) < 14 * 24 * 3600
  for: 1h
  labels:
    severity: warning
  annotations:
    summary: "SSL certificate expires in less than 14 days"
```

---

### Scenario 6: Application Deployment Rollback

**Situation:** New payment service version (v2.0) has a bug causing payment failures. Need to rollback to v1.9.

```bash
# Step 1: Check current deployment status
kubectl get deployment payment-service -n production -o wide
kubectl rollout history deployment/payment-service -n production

# Step 2: Check what's wrong with new version
kubectl logs -n production deployment/payment-service --tail=50
kubectl get events -n production --sort-by='.lastTimestamp'

# Step 3: Rollback to previous version
kubectl rollout undo deployment/payment-service -n production

# Or rollback to specific revision
kubectl rollout undo deployment/payment-service -n production --to-revision=3

# Step 4: Monitor rollback progress
kubectl rollout status deployment/payment-service -n production

# Step 5: Verify pods are running with old version
kubectl get pods -n production -l app=payment-service -o wide
kubectl describe pod <pod-name> -n production | grep Image

# Step 6: Verify application is healthy
kubectl exec -it <pod-name> -n production -- curl localhost:8080/health

# Step 7: Monitor payment success rate
# Check Prometheus/Grafana for payment_success_rate metric
```

**Best Practice:** Use Deployment strategy
```yaml
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 0      # Never take down existing pods
      maxSurge: 25%          # Add 25% more pods during update
  minReadySeconds: 30        # Wait 30s before marking pod ready
```

---

### Scenario 7: Node Failure During Peak Traffic

**Situation:** One of three worker nodes failed during Black Friday sale. Payment pods are down.

```bash
# Step 1: Check node status
kubectl get nodes
# Shows: node-3  NotReady

# Step 2: Check affected pods
kubectl get pods -A -o wide --field-selector spec.nodeName=node-3
kubectl get pods -n production -l app=payment-service

# Step 3: Check pod disruption budget
kubectl get pdb -n production
# Ensure PDB allows rescheduling

# Step 4: Force pod rescheduling (if stuck in Terminating)
kubectl delete pod <stuck-pod> -n production --grace-period=0 --force

# Step 5: Check if new pods are scheduled
kubectl get pods -n production -l app=payment-service -w

# Step 6: If pods pending, check why
kubectl describe pod <pending-pod> -n production
# Look for: Insufficient cpu, Insufficient memory, node affinity

# Step 7: Temporarily relax anti-affinity if needed
kubectl patch deployment payment-service -n production --type=json \
  -p='[{"op": "remove", "path": "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution"}]'

# Step 8: Scale up to handle load on fewer nodes
kubectl scale deployment payment-service -n production --replicas=10

# Step 9: Monitor cluster resources
kubectl top nodes
kubectl top pods -n production
```

**Prevention:** Use topology spread constraints
```yaml
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: ScheduleAnyway  # Don't block scheduling
    labelSelector:
      matchLabels:
        app: payment-service
```

---

### Scenario 8: Security Incident - Suspicious Pod Activity

**Situation:** Security team detected unusual outbound traffic from payment namespace.

```bash
# Step 1: Identify suspicious pods
kubectl get pods -n payment -o wide
kubectl top pods -n payment  # Check for unusual resource usage

# Step 2: Check pod network connections
kubectl exec -it <suspicious-pod> -n payment -- netstat -tulpn
kubectl exec -it <suspicious-pod> -n payment -- ss -tulpn

# Step 3: Check running processes
kubectl exec -it <suspicious-pod> -n payment -- ps aux

# Step 4: Check pod events and logs
kubectl describe pod <suspicious-pod> -n payment
kubectl logs <suspicious-pod> -n payment --tail=500

# Step 5: Isolate the pod immediately (Network Policy)
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-suspicious-pod
  namespace: payment
spec:
  podSelector:
    matchLabels:
      app: <suspicious-app>
  policyTypes:
    - Ingress
    - Egress
  # Empty ingress/egress = deny all traffic
EOF

# Step 6: Check image for vulnerabilities
kubectl get pod <suspicious-pod> -n payment -o jsonpath='{.spec.containers[*].image}'
trivy image <image-name>

# Step 7: Check who deployed the pod
kubectl get pod <suspicious-pod> -n payment -o jsonpath='{.metadata.annotations}'

# Step 8: Check audit logs
# On master node or audit log storage
grep "payment" /var/log/kubernetes/audit/audit.log | grep "create"

# Step 9: Delete suspicious pod after evidence collection
kubectl delete pod <suspicious-pod> -n payment

# Step 10: Rotate all credentials in payment namespace
kubectl delete secret --all -n payment
# Recreate secrets with new credentials
```

---

### Scenario 9: Horizontal Pod Autoscaler Not Scaling

**Situation:** HPA shows high CPU but not scaling up pods during sale.

```bash
# Step 1: Check HPA status
kubectl get hpa -n production
kubectl describe hpa frontend-hpa -n production

# Step 2: Check if metrics server is running
kubectl get pods -n kube-system | grep metrics-server
kubectl top pods -n production  # If this fails, metrics-server issue

# Step 3: Check metrics server logs
kubectl logs -n kube-system deployment/metrics-server

# Step 4: Verify deployment has resource requests (required for HPA)
kubectl get deployment frontend -n production -o yaml | grep -A10 resources
# HPA needs resource requests to calculate utilization

# Step 5: Check if maxReplicas reached
kubectl get hpa frontend-hpa -n production -o yaml | grep maxReplicas

# Step 6: Check cluster resources
kubectl describe nodes | grep -A5 "Allocated resources"
# If nodes are full, pods can't be scheduled

# Step 7: Fix: Add resource requests if missing
kubectl patch deployment frontend -n production --type=json \
  -p='[{"op": "add", "path": "/spec/template/spec/containers/0/resources", "value": {"requests": {"cpu": "100m", "memory": "128Mi"}}}]'

# Step 8: Fix: Increase maxReplicas
kubectl patch hpa frontend-hpa -n production -p '{"spec":{"maxReplicas": 100}}'

# Step 9: Fix: Add more nodes if cluster is full
# Cloud provider specific - e.g., for EKS:
eksctl scale nodegroup --cluster=prod --name=ng-1 --nodes=10
```

---

### Scenario 10: Ingress Not Routing Traffic

**Situation:** New microservice deployed but returns 404 from ingress.

```bash
# Step 1: Check ingress resource
kubectl get ingress -n production
kubectl describe ingress ecommerce-ingress -n production

# Step 2: Check if backend service exists
kubectl get svc -n production | grep <service-name>

# Step 3: Check if service has endpoints
kubectl get endpoints <service-name> -n production
# Empty endpoints = no healthy pods matching service selector

# Step 4: Check service selector matches pod labels
kubectl get svc <service-name> -n production -o yaml | grep -A5 selector
kubectl get pods -n production --show-labels | grep <app-label>

# Step 5: Check ingress controller logs
kubectl logs -n ingress-nginx deployment/ingress-nginx-controller --tail=100 | grep <path>

# Step 6: Check if ingress class matches
kubectl get ingressclass
kubectl get ingress ecommerce-ingress -n production -o yaml | grep ingressClassName

# Step 7: Test from inside cluster
kubectl run debug --image=curlimages/curl -it --rm -- curl -v http://<service-name>.<namespace>.svc.cluster.local

# Step 8: Check ingress controller configuration
kubectl exec -it -n ingress-nginx deployment/ingress-nginx-controller -- cat /etc/nginx/nginx.conf | grep -A20 <host>

# Step 9: Common fixes
# Fix wrong service port:
kubectl patch ingress ecommerce-ingress -n production --type=json \
  -p='[{"op": "replace", "path": "/spec/rules/0/http/paths/0/backend/service/port/number", "value": 8080}]'
```

---

### Scenario 11: etcd Cluster Recovery

**Situation:** etcd cluster is unhealthy, only 1 of 3 members responding.

```bash
# Step 1: Check etcd cluster health
ETCDCTL_API=3 etcdctl endpoint health \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key

# Step 2: List etcd members
ETCDCTL_API=3 etcdctl member list \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key

# Step 3: Check etcd logs on failed nodes
journalctl -u etcd -n 100
# or for kubeadm:
docker logs $(docker ps -a | grep etcd | awk '{print $1}')

# Step 4: Remove failed member
ETCDCTL_API=3 etcdctl member remove <member-id> \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key

# Step 5: Add new member (after fixing the node)
ETCDCTL_API=3 etcdctl member add etcd-node3 \
  --peer-urls=https://192.168.1.13:2380 \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key

# Step 6: Restore from backup (worst case)
ETCDCTL_API=3 etcdctl snapshot restore backup.db \
  --data-dir=/var/lib/etcd-new \
  --initial-cluster=etcd-node1=https://192.168.1.11:2380
```

---

### Scenario 12: ConfigMap/Secret Hot Reload

**Situation:** Need to update payment gateway API keys without restarting pods.

```bash
# Step 1: Check current secret
kubectl get secret payment-credentials -n production -o yaml

# Step 2: Update the secret
kubectl create secret generic payment-credentials \
  --from-literal=API_KEY=new-key-value \
  --from-literal=API_SECRET=new-secret-value \
  -n production \
  --dry-run=client -o yaml | kubectl apply -f -

# Step 3: Check if application supports hot reload
# If using volume mount:
kubectl exec -it payment-pod -n production -- cat /etc/secrets/API_KEY
# Kubernetes updates volume-mounted secrets automatically (may take ~1 min)

# Step 4: If using env vars, must restart pod
kubectl rollout restart deployment/payment-service -n production

# Step 5: Better approach - Use Reloader
# Install: https://github.com/stakater/Reloader
# Add annotation to deployment:
kubectl annotate deployment payment-service -n production \
  reloader.stakater.com/auto="true"

# Now when secret changes, Reloader automatically restarts pods
```

**Best Practice for secrets hot reload:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-service
  annotations:
    reloader.stakater.com/auto: "true"  # Auto reload on secret/configmap change
spec:
  template:
    spec:
      containers:
        - name: payment
          volumeMounts:
            - name: secrets
              mountPath: /etc/secrets
              readOnly: true
      volumes:
        - name: secrets
          secret:
            secretName: payment-credentials
```

---

### Scenario 13: Debug Memory Leak in Production

**Situation:** Payment service pods keep getting OOMKilled.

```bash
# Step 1: Check OOMKilled events
kubectl get pods -n production -l app=payment-service
kubectl describe pod <pod-name> -n production | grep -A10 "Last State"

# Step 2: Check memory usage over time
kubectl top pods -n production -l app=payment-service

# Step 3: Check resource limits
kubectl get deployment payment-service -n production -o yaml | grep -A10 resources

# Step 4: Get heap dump before OOM (if Java)
kubectl exec -it <pod-name> -n production -- jmap -dump:format=b,file=/tmp/heap.hprof <pid>
kubectl cp <pod-name>:/tmp/heap.hprof ./heap.hprof -n production

# Step 5: Check container metrics
kubectl exec -it <pod-name> -n production -- cat /sys/fs/cgroup/memory/memory.usage_in_bytes

# Step 6: Temporary fix - Increase memory limit
kubectl patch deployment payment-service -n production --type=json \
  -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/resources/limits/memory", "value": "1Gi"}]'

# Step 7: Enable vertical pod autoscaler for recommendations
kubectl get vpa payment-service-vpa -n production -o yaml
# Check recommended resources

# Step 8: Long-term fix
# - Profile application memory usage
# - Fix memory leaks in code
# - Set appropriate JVM heap settings (for Java)
# - Use VPA to automatically right-size resources
```

---

### Scenario 14: Blue-Green Deployment for Payment Service

**Situation:** Deploy new version with zero downtime and instant rollback capability.

```bash
# Step 1: Current state - Blue deployment serving traffic
kubectl get deployment payment-blue -n production
kubectl get svc payment-service -n production -o yaml | grep selector
# selector: version: blue

# Step 2: Deploy Green version alongside Blue
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-green
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: payment-service
      version: green
  template:
    metadata:
      labels:
        app: payment-service
        version: green
    spec:
      containers:
        - name: payment
          image: payment-service:v2.0
EOF

# Step 3: Wait for Green to be ready
kubectl rollout status deployment/payment-green -n production

# Step 4: Test Green deployment internally
kubectl run test --image=curlimages/curl -it --rm -- \
  curl http://payment-green.production.svc.cluster.local/health

# Step 5: Switch traffic to Green
kubectl patch svc payment-service -n production \
  -p '{"spec":{"selector":{"app":"payment-service","version":"green"}}}'

# Step 6: Monitor for errors
# Watch Prometheus/Grafana for error rates

# Step 7: Rollback if needed (switch back to Blue)
kubectl patch svc payment-service -n production \
  -p '{"spec":{"selector":{"app":"payment-service","version":"blue"}}}'

# Step 8: Cleanup old Blue deployment after successful rollout
kubectl delete deployment payment-blue -n production
```

---

### Scenario 15: Implement Rate Limiting for API

**Situation:** Prevent abuse of payment API - limit to 100 requests per minute per user.

```yaml
# Using NGINX Ingress annotations
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: payment-api-ingress
  namespace: production
  annotations:
    # Rate limiting
    nginx.ingress.kubernetes.io/limit-rps: "10"           # 10 req/sec
    nginx.ingress.kubernetes.io/limit-rpm: "100"          # 100 req/min
    nginx.ingress.kubernetes.io/limit-connections: "5"    # 5 concurrent

    # Custom error when rate limited
    nginx.ingress.kubernetes.io/server-snippet: |
      limit_req_status 429;

    # Rate limit by header (e.g., API key)
    nginx.ingress.kubernetes.io/configuration-snippet: |
      limit_req_zone $http_x_api_key zone=api_limit:10m rate=10r/s;
      limit_req zone=api_limit burst=20 nodelay;
spec:
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /payments
            pathType: Prefix
            backend:
              service:
                name: payment-api
                port:
                  number: 8080
```

**Test rate limiting:**
```bash
# Send multiple requests quickly
for i in {1..150}; do
  curl -s -o /dev/null -w "%{http_code}\n" https://api.example.com/payments/health
done | sort | uniq -c
# Should see some 429 responses
```

---

## 12. Quick Scenario Reference Card

| Scenario | First Command | Key Actions |
|----------|---------------|-------------|
| **Pod not starting** | `kubectl describe pod` | Check events, image pull, resources |
| **Service unreachable** | `kubectl get endpoints` | Check selector, pods healthy |
| **SSL issues** | `openssl s_client -connect` | Check cert expiry, secret mounted |
| **High latency** | `kubectl top pods` | Check resources, HPA, network |
| **OOMKilled** | `kubectl describe pod` | Increase limits, check leaks |
| **Deployment stuck** | `kubectl rollout status` | Check resources, node capacity |
| **Ingress 404** | `kubectl describe ingress` | Check backend service, endpoints |
| **etcd issues** | `etcdctl endpoint health` | Check member status, restore |
| **Node NotReady** | `kubectl describe node` | Check kubelet, disk, network |
| **Security incident** | `kubectl get pods -o wide` | Isolate, logs, audit |

---

## Good Luck! 🚀

Remember:
- Always think about **security first** for payment systems
- **High availability** is critical for e-commerce
- **SSL/TLS** must be properly configured and monitored
- **Compliance** (PCI-DSS) is mandatory for payment processing
- **Monitoring and alerting** prevents downtime
