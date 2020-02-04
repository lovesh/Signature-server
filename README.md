# Signature server

## Overview
Code written as part of an interview-assignment. The requirements were something like these:
1. Write a program in Rust called Signature Server, with a REST API that communicates with JSON objects.
1. The server is configured via a configuration file that specifies:
    - The port to listen for HTTP requests on
    - An ed25519 private key or keypair to be used as the “daemon key” below.
1. The endpoints to handle are the following:
    - GET /public_key: Returns a JSON object containing the public key of the
      daemon key.
    - PUT /transaction: Takes a blob of data (arbitrary bytes) representing the
      transaction data in the form of a base64 string, and remembers it in memory.
      Returns a random, unique identifier for the transaction.
    - POST /signature​: Takes a list of transaction identifiers, and builds a
      JSON array of strings containing the base64-encoded transaction blobs
      indicated by the given identifiers. It signs this array (serialised as JSON
      without any whitespace) using the daemon private key. Finally, it returns the
      array that was signed, as well as the signature as a base64 string.
      Example​. Suppose that the POST request contained the identifiers of, in
      order, two transactions that have blobs [255, 224, 1, 2, 3] and [4, 5, 6, 7, 8]
      (both are 5 bytes long). In base64, these respectively become ​/+ABAgM=​ and
      BAUGBwg=​. The string to sign then is ​["/+ABAgM=","BAUGBwg="]​

Using Actix-web. 

## Dev instructions
1. The config file containing the port and keys is not checked into the code since in production such files will be managed by the CI. 
Its named `Config.toml` and lives in the root of the crate (same level as `src` directory).
1. For testing I have been using file with these contents. 
    ```
    [deployment]
    port = 8000
    
    [public_keys]
    public_key = "TaxyY3G2A3pw7t2YSNtp88rRMV2G2GAasfldraakCZ8="
    
    [private_keys]
    private_key = "pIwwiWYMzK1vd/aPWQWYW254d6RaqVY1M3ocUiFxKY8="
    ```
    A file with same contents is present in the repo with name [Sample_Config.toml](./Sample_Config.toml). It can be renamed 
    to `Config.toml` and used as well. The tests also assume presence of this file.

## TODOs
1. Break large tests into multiple small ones
1. Request-response versioning