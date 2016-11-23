# The data format

A share consists of two parts:

## 1. The content plus IC info

This is just one binary blob consisting of the raw secret-shared data,
immediately followed by the IC data (if present)

## 2. The metadata necessary for reconstruction

The metadata are supposed to be stored together with the binary data in
the form of a simple dictionary (a.k.a. `<String, String> Map`) - almost
all cloud storage providers allow for this (or are in the process of
implementing it).

The metadata common to all share formats (as returned by
`Share.getCommonMetaData()`) are currently the following:

* #### "archistar-share-type"

    this is currently one of: "SHAMIR", "RABIN", "KRAWCZYK",
    "NTT_SHAMIR", "NTT_RABIN" (see below)

* #### "archistar-version"

    this is the version number of the share format and is
    currently "4"

* #### "archistar-id"

    this is the x-value of the share

* #### "archistar-ic-type"

    this is one of:
    * "0" for no information checking
    * "1" for Rabin-Ben-Or information checking (see informationchecking/RabinBenOrRSS)
    * "2" for Cevallos information checking (se informationchecking/CevallosUSRSS)

* #### "archistar-length"

    this is the length (in bytes) of the raw share data, and is used
    to determine the starting point of the IC info



The metadata specific to each share type are:

### 2a. SHAMIR (see data/ShamirShare)

no extra data

### 2b. RABIN (see data/RabinShare)

* #### "archistar-original-length"

   this is the length of the original (unshared, complete) file

### 2c. KRAWCZYK (see data/KrawczykShare)

* #### "archistar-original-length"

    this is the length of the original (unshared, complete) file

* #### "archistar-krawczyk-algorithm"

    this is the algorithm used to encrypt the original data
    (currently unused)
        
* #### "archistar-krawczyk-key"
    
    the key used to encrypt the original data
    (the original key is distributed over all shares via ShamirPSS
    and then - for robustness - Base64-encoded)
        
### 2d. NTT_SHAMIR (see data/NTTShamirShare)

* #### "archistar-original-length"

    this is the length of the original (unshared, complete) file

* #### "archistar-ntt-share-size"

    ?

### 2e. NTT_RABIN (see data/NTTRabinShare)

* #### "archistar-original-length"

    this is the length of the original (unshared, complete) file

* #### "archistar-ntt-share-size"

    ?