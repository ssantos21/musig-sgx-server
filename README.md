# Intel SGX Enclave Server

This application is a minimum example for running secured application with Intel SGX enclave.

## Intel SGX Drivers and SDK Installation

To install and setup Intel SGX drivers and SDK, follow the steps described in [Intel SGX for Linux repository](https://github.com/intel/linux-sgx).

## Build and run this application

Build and run this application as follows.

```
# clone this repo
$ git clone https://github.com/ssantos21/blinded-musig-sgx-server
$ cd blinded-musig-sgx-server
# build application (simulator mode)
$ make SGX_MODE=SIM INCLUDE_SECP256K1_ZKP=1
# run application
$ ./app
```

## More MAKE commands

After the initial build, the main project can be built without `INCLUDE_SECP256K1_ZKP=1`.
```
$ make SGX_MODE=SIM
```

To clean the project (`INCLUDE_SECP256K1_ZKP=1` can also be ommited so only the main project is cleaned).
```
$ make clean INCLUDE_SECP256K1_ZKP=1
```