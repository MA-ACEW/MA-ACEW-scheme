# MA-ACEW & EB-PS Benchmark Implementation

This repository contains Go implementations of two cryptographic schemes:

- **EB-PS** (Epoch-Bound Pointcheval-Sanders Signature)
- **MA-ACEW** (Multi-Authority Anonymous Credentials with Epoch-Based Weights)

The implementation includes benchmarking functions for evaluating the performance of these schemes.

---

## Acknowledgement of External Code

Parts of this implementation reuse and adapt open-source code from **Das et al.** (see [https://github.com/sourav1547/wts](https://github.com/sourav1547/wts)).  
For transparency and proper attribution, we have added comments in each relevant file to indicate the reused portions.

---

## Code Structure

- `maacew/src/`  
  Go implementation of **EB-PS** and **MA-ACEW** schemes.

- `maacew/contracts/`  
  Solidity implementation for smart contract integration.

---

## Dependencies

- [Go](https://golang.org/) **version 1.19.x or higher**  
- Tested on **Ubuntu**

---

## Running Benchmarks

We provide two main benchmark entry points. Other test functions are also available and can be run individually, but the following are the key benchmarks:

### EB-PS Benchmark
Run the benchmark for EB-PS operations:

```bash
cd maacew/src
go test -v -bench=BenchmarkAllEBPSOperations -run=^#
```


#### MA-ACEW Benchmark
Run the benchmark for MA-ACEW with thresholds:
```bash
cd maacew/src
go test -v -bench=BenchmarkShowAndVerifyWithThresholds -run=^#
```
