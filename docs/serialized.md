# What the shared data looks like

For various reasons (enumerated below) we decided on a split representation
of the shared data: on the one side, there is the raw secret-shared data
in the form of a simple linear byte array, with the serialized Information
Checking data (if present) concatenated at the end. On the other side there
is all the metadata necessary to reconstruct the original data, contained in
a simple dictionary (a.k.a. key/value store a.k.a. <String, String> Map).

There is thus no fully (that is: byte-for-byte) specified on-disk format.

# Rationale

Almost all cloud storage providers allow some form of metadata to be stored
together with files, or are in the process of implementing this feature.

In all instances, the metadata can be used like a key/value store, and can
be updated separately from the file, and retrieved both separately and together
with the file.

We can thus depend on this as a standard feature and use it to facilitate and
speed up file handling. If we just need the metadata, we can quickly and easily
get them; if we require both the data and the metadata, we can retrieve them
in one request.

Also, if for some reason we cannot depend on this feature, there is still
the possibility of just serializing the metadata as a JSON map (as for
example in the on-disk backend of archistar-smc-tools) and storing it together
with the binary file.

To be clear: the handling (converting, storing, retrieving) of the metadata
is the responsibility of the client of this library.

#### Provider-specific metadata limits

* Amazon S3:

    "The maximum size for user metadata is 2 KB, and both the keys and their
    values must conform to US-ASCII standards."

    http://docs.aws.amazon.com/AmazonS3/latest/UG/EditingtheMetadataofanObject.html

* Google Drive:

    * Maximum of 100 custom properties per file, totaled from all sources.
    * Maximum of 30 public properties per file, totaled from all sources.
    * Maximum of 30 private properties per file from any one application.
    * Maximum of 124 bytes size per property (including both key and value)
    string in UTF-8 encoding. For example, a property with a key that is
    ten characters long can only have 114 characters in the value. A property
    that requires 100 characters for the value can use up to 24 characters
    for the key.

    https://developers.google.com/drive/v3/web/properties

* Microsoft Azure:

    "The total size of the metadata, including both the name and value
    together, may not exceed 8 KB in size. "

    https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/Setting-and-Retrieving-Properties-and-Metadata-for-Blob-Resources

* Dropbox: There are some hints in the documentation of the new API that point
towards the existence of the possibility of using custom properties on files,
requiring the prior definition of a template ("PropertyGroup"). The limits per
template seem to be: 32 properties, up to 256 bytes for names, up to 1024 bytes
for values.

# The data format

### 1. Binary

This is just one binary blob consisting of the raw secret-shared data,
immediately followed by the IC data (if present)

### 2. Metadata

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
