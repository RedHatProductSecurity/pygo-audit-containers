# Explaining the Prometheus image

We inspected the Linux/AMD64 version of the Prometheus image. The output
reports about 114 MB spread across nine image layers. Two layers, at 61.91 MB
and 50.99 MB, account for almost all of that size. The remaining seven are
much smaller. This listing gives us each layer's size and digest, but we would
need to inspect its contents to say which files it contains.

Think of the layers as successive sets of filesystem changes. Each can add,
replace, or remove files. Applying them in order produces the filesystem that
the image supplies to a container. A file replaced or removed by a later
layer no longer appears in that final view, although its earlier content can
remain in an older layer. The [image layer specification](https://github.com/opencontainers/image-spec/blob/main/layer.md)
describes how these changes are combined.

The `/prometheus` entry under `Volumes` describes a separate storage concern.
The startup command tells Prometheus to write its time-series database there.
A volume mounted at that location holds runtime data separately from the
image layers, so the nine layers and their reported 114 MB do not tell us how
much metric data a running deployment has stored. The volume declaration
alone also does not show an actual mounted volume or its capacity.
[Docker's volume documentation](https://docs.docker.com/engine/storage/volumes/)
explains this separation.

For our pygo-audit demonstration, we will extract the image into one merged
filesystem and examine the Go binaries found there. That gives us the packaged
software to audit. A running deployment's mounted data and the contents of
earlier, superseded layers would require separate inspection.

The exact Linux/AMD64 image selected in this output is:

```text
quay.io/prometheus/prometheus@sha256:86b17a25c2db1d16a61b16b3c8f336679eb19e26333d03e808da387206e40faa
```

Using this digest lets us return to the same image even if the `latest` tag
later changes. The separate `Manifest List` digest identifies the collection
from which this platform-specific image was selected.
