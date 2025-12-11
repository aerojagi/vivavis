🚀 Talos Kubernetes Cluster Setup with Rook-Ceph & Harbor Registry
This guide describes how to:

Create a Kubernetes cluster on Talos Linux
Deploy Rook-Ceph for persistent storage
Install Harbor as a private container registry
Push custom images and integrate with Kubernetes workloads


✅ 1. Talos Kubernetes Cluster Setup
Goal
Provision a Talos-based Kubernetes cluster and validate its readiness.
Prerequisites

talosctl installed on your admin machine
Internet access for nodes (or registry mirror for air-gapped setups)
Matching versions of Talos and talosctl
Talos ISO from https://factory.talos.dev
Fixed IPs for control-plane and workers


Steps
Phase A – Preparation
Shell# Install talosctl locallycurl -sL https://github.com/siderolabs/talos/releases/latest/download/talosctl-linux-amd64 -o /usr/local/bin/talosctlchmod +x /usr/local/bin/talosctl# Define cluster name and endpointexport CLUSTER_NAME=myclusterexport ENDPOINT=https://<CONTROL_PLANE_IP_or_VIP>:6443Weitere Zeilen anzeigen
Phase B – Boot & Config
Boot nodes from Talos ISO, then generate configs:
Shell# Optional: Disable default CNI for Calico/Cilium latercat > patch.yaml <<'YAML'cluster:  network:    cni:      name: noneYAMLtalosctl gen config "$CLUSTER_NAME" "$ENDPOINT" --config-patch @patch.yamlWeitere Zeilen anzeigen
Apply configs:
Shelltalosctl apply-config --insecure --nodes <CP_IP> --file controlplane.yamltalosctl apply-config --insecure --nodes <WORKER_IPs> --file worker.yamlWeitere Zeilen anzeigen
Bootstrap and fetch kubeconfig:
Shellexport TALOSCONFIG=./talosconfigtalosctl config endpoint <CP_IP>talosctl config node <CP_IP>talosctl bootstrap --nodes <CP_IP>Weitere Zeilen anzeigen
Phase C – Validate
Shellkubectl --kubeconfig=./kubeconfig get nodes -o wideWeitere Zeilen anzeigen

✅ 2. Deploy Rook-Ceph for Block Storage
Prerequisites

Talos cluster running
Additional disk /dev/sdb on each node for Ceph OSDs

Steps
Check disks
Shelltalosctl -n <NODE_IP> get disk# Optional wipe if reused:talosctl -n <NODE_IP> wipe --device /dev/sdbWeitere Zeilen anzeigen
Install Rook-Ceph
Shellkubectl create ns rook-cephkubectl apply -f https://raw.githubusercontent.com/rook/rook/release-1.14/deploy/examples/crds.yamlkubectl apply -f https://raw.githubusercontent.com/rook/rook/release-1.14/deploy/examples/common.yamlkubectl apply -f https://raw.githubusercontent.com/rook/rook/release-1.14/deploy/examples/operator.yamlWeitere Zeilen anzeigen
CephCluster config
YAMLapiVersion: ceph.rook.io/v1kind: CephClustermetadata:  name: rook-ceph  namespace: rook-cephspec:  cephVersion:    image: quay.io/ceph/ceph:v18.2.2  dataDirHostPath: /var/lib/rook  mon:    count: 3  storage:    useAllNodes: true    useAllDevices: false    devices:      - name: "sdb"Weitere Zeilen anzeigen
Apply:
Shellkubectl apply -f cephcluster.yamlWeitere Zeilen anzeigen
Create BlockPool & StorageClass
YAML# blockpool.yamlapiVersion: ceph.rook.io/v1kind: CephBlockPoolmetadata:  name: ceph-blockpool  namespace: rook-cephspec:  failureDomain: host  replicated:    size: 3Weitere Zeilen anzeigen
YAML# storageclass.yamlapiVersion: storage.k8s.io/v1kind: StorageClassmetadata:  name: rook-ceph-blockprovisioner: rook-ceph.rbd.csi.ceph.comparameters:  clusterID: rook-ceph  pool: ceph-blockpoolallowVolumeExpansion: truereclaimPolicy: DeletevolumeBindingMode: WaitForFirstConsumerWeitere Zeilen anzeigen
Set default:
Shellkubectl patch storageclass rook-ceph-block --type=merge --patch '{"metadata":{"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'Weitere Zeilen anzeigen
Test PVC
YAMLapiVersion: v1kind: PersistentVolumeClaimmetadata:  name: ceph-test-pvcspec:  accessModes: [ReadWriteOnce]  storageClassName: rook-ceph-block  resources:    requests:      storage: 1GiWeitere Zeilen anzeigen

✅ 3. Harbor Registry Setup
Prerequisites

Helm installed
Rook-Ceph StorageClass available
Harbor admin credentials

Steps
Install Harbor
Shellkubectl create ns harborhelm repo add harbor https://helm.goharbor.io && helm repo updatehelm install harbor harbor/harbor --namespace harbor -f harbor-values.yamlWeitere Zeilen anzeigen
Sample harbor-values.yaml
YAMLexpose:  type: nodePort  tls:    enabled: false  nodePort:    http:      port: 30002externalURL: http://10.200.0.1:30002harborAdminPassword: "<HARBOR_ADMIN_PASSWORD>"persistence:  enabled: true  resourcePolicy: "keep"  persistentVolumeClaim:    registry:   { storageClass: rook-ceph-block, size: 50Gi }    database:   { storageClass: rook-ceph-block, size: 10Gi }    redis:      { storageClass: rook-ceph-block, size: 5Gi }    trivy:      { storageClass: rook-ceph-block, size: 20Gi }Weitere Zeilen anzeigen
Configure Talos mirror
YAMLmachine:  registries:    mirrors:      "10.200.0.1:30002":        endpoints:          - "http://10.200.0.1:30002"Weitere Zeilen anzeigen
Apply:
Shelltalosctl patch mc --nodes <IPs> --patch @harbor-mirror-patch.yamlWeitere Zeilen anzeigen

Push Images
Shellsudo docker login 10.200.0.1:30002sudo docker tag keycloak/keycloak:26.4.2 10.200.0.1:30002/device-manager/keycloak:26.4.2sudo docker push 10.200.0.1:30002/device-manager/keycloak:26.4.2Weitere Zeilen anzeigen

Kubernetes Integration
Shellkubectl create ns device-managerkubectl -n device-manager create secret docker-registry harbor-creds \  --docker-server=10.200.0.1:30002 \  --docker-username=admin \  --docker-password="<HARBOR_ADMIN_PASSWORD>"Weitere Zeilen anzeigen
ServiceAccount:
YAMLapiVersion: v1kind: ServiceAccountmetadata:  name: dm-serviceaccount  namespace: device-managerimagePullSecrets:  - name: harbor-credsWeitere Zeilen anzeigen
Test Pod:
YAMLapiVersion: v1kind: Podmetadata:  name: harbor-test  namespace: device-managerspec:  serviceAccountName: dm-serviceaccount  containers:    - name: dm-test      image: 10.200.0.1:30002/device-manager/device-manager:20251118      imagePullPolicy: Always      command: ["sleep", "3600"]Weitere Zeilen anzeigen

✅ Best Practices

Use TLS for Harbor and distribute CA cert to Talos nodes.
Create robot accounts for image pushes.
Enable Trivy scanning and immutable tags in Harbor.
Regularly monitor Ceph health (ceph -s) and plan upgrades.


✅ Troubleshooting

ImagePullBackOff → Check secret type and network reachability.
HEALTH_WARN in Ceph → Ensure enough OSDs or adjust pool size for lab.
Harbor unreachable → Verify NodePort and firewall rules.
