# KOSS - Kubernetes OS Server

KOSS is a [Extension API Server](https://kubernetes.io/docs/tasks/extend-kubernetes/setup-extension-api-server/) which exposes OS properties and functionality using Kubernetes API, so it can be accessed using e.g. `kubectl`.

At the moment this is highly experimental and only managing `sysctl` is supported. To make things actually usable, you must run KOSS binary as root on the machine you will be managing.

Managing multiple machines is not supported and not planned.

KOSS also do not use any of libraries to build Kubernetes API, but builts it's absolute minimal version from scratch, which is most likely missing many features.

Listing, getting and editing sysctl is only working functionality.

KOSS exposes API over HTTPS using self-signed X.509 certificate generated on the fly on server start.

## Testing

To test it out, modify [manifest.yaml](manifest.yaml) YAML file and set `externalName` field to IP where KOSS will be available under right now hardcoded port 8443.

Then, apply this manifest on your cluster using e.g. `kubectl apply -f` command.

Now, you should be able to read your sysctl values using `kubectl get sysctl` like on example below:

```console
$ kubectl get sysctl | head
NAME                                 VALUE
abi.vsyscall32                       1
debug.exception-trace                1
debug.kprobes-optimization           1
dev.hpet.max-user-freq               64
dev.i915.oa_max_sample_rate          100000
dev.i915.perf_stream_paranoid        1
dev.mac_hid.mouse_button2_keycode    97
dev.mac_hid.mouse_button3_keycode    100
dev.mac_hid.mouse_button_emulation   0
```

You can also write values using `kubectl patch` or `kubectl edit`:

```sh
kubectl patch sysctl vm.overcommit_ratio -p '{"value":"50"}'
```

As well as by applying a specific manifest:

```sh
cat <<EOF | kubectl apply -f-
apiVersion: koss.invidian.github.io/v1alpha1
kind: Sysctl
metadata:
  name: vm.overcommit_ratio
value: "50"
EOF
```
