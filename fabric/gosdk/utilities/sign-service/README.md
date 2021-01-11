# Signing service for vsock

这段代码是为了通过vsock暴露ecdsa sign服务，在KVM guest里可以正常运行，但是在
nitro enclave里运行遇到以下问题

```shell
[    0.441281] nsm: module verification failed: signature and/or required key missing - tainting kernel
2021/01/11 10:40:52 Run as server...
2021/01/11 10:42:53 connection closed
crypto/rand: blocked for 60 seconds waiting to read random data from the kernel
Connection to 54.86.161.97 closed by remote host.
Connection to 54.86.161.97 closed.
```

初步怀疑是nitro enclave禁止应用获取随机数导致的问题。
