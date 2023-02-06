# Rancher + Helm + K3s install
- https://rancher.com/docs/rancher/v2.6/en/quick-start-guide/deployment/quickstart-manual-setup/#install-rancher-with-helm
```bash
# K3S
curl -sfL https://get.k3s.io | sh -s - server
# Copy config to workstation 

scp root@<IP_OF_LINUX_MACHINE>:/etc/rancher/k3s/k3s.yaml ~/.kube/config

# Install Helm
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh

# Helm configs

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

helm repo add rancher-latest https://releases.rancher.com/server-charts/latest

kubectl create namespace cattle-system

sudo chmod 644 /etc/rancher/k3s/k3s.yaml

kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.5.1/cert-manager.crds.yaml

helm repo add jetstack https://charts.jetstack.io

helm repo update

helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version v1.5.1

# WAIT FOR ROLLOUT OF CERT-MANAGER TO COMPLETE
kubectl -n cert-managerm rollout status deploy/cert-manager

# Install Rancher
helm install rancher rancher-latest/rancher \
  --namespace cattle-system \
  --set hostname=<IP_OF_LINUX_NODE>.sslip.io \
  --set replicas=1 \
  --set bootstrapPassword=<PASSWORD_FOR_RANCHER_ADMIN>
```

# Virtualbox no network fix

- VBoxManage natnetwork stop  --netname NatNetwork
- VBoxManage natnetwork start  --netname NatNetwork

# Harvester install
- https://docs.harvesterhci.io/v1.0/
Follow along with ISO. It will create a VIP which the admin interface will be on.
Passwd: 
- admin:QWTGJQpeMD67QtuqDlaS

## Harvester + Rancher combo
- (Techotim video on harvester)




# Helm delete
```bash
# Get all releases
helm ls --all-namespaces
# OR
helm ls -A

# Delete release
helm uninstall release_name -n release_namespace
```

# Some kubectl commands
- https://kubernetes.io/docs/reference/kubectl/cheatsheet/

# Reset harv password
```bash
kubectl  -n cattle-system exec $(kubectl --kubeconfig $KUBECONFIG -n cattle-system get pods -l app=rancher --no-headers | head -1 | awk '{ print $1 }') -c rancher -- reset-password

```

# resources not viewed yet
- https://www.cyberark.com/resources/threat-research-blog/kubernetes-pentest-methodology-part-3
- https://github.com/cyberark/kubernetes-rbac-audit
- https://www.cyberark.com/resources/threat-research-blog/kubernetes-pentest-methodology-part-1
- https://github.com/ropnop/pentest_charts