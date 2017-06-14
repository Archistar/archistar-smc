Version 0.4
===========

0.2 and 0.3 were project-internal releases. As we do not want to fsck up existing
builds we are thus jumping up to 0.4.

The unsung hero and most valuable player of this release is Florian Wohner who
did all the important parallelization work.

This was a rather ''interesting'' release. We switchted to the bouncycastle crypto
library and allowed modular arithmetic (mostly to try GF^257 based cryptographic
algorithms). Later we found out, that the performance was really hurt as Java does
not provide any preprocessor-like functionalities that would allow for efficient
switchable mathematics.

This in turn was followed by a period of minimization and reducing options. Florian
added the really important Rabin parallelization code as well as additional
cryptographic algorithms.

To sum up, on a four core processor we have an encoding improvement for Shamir of
+107%, Rbin +670% and for Krawcywk with Salsa20 of +167%. Decoding got improved
too: shamir +204%, Rabin +140% and Krawczyk by +98%.

Andreas Happe (85):
 * bump version to 0.2-wip
 * drop support for java 1.6/java6se
 * Merge branch 'master' of github.com:Archistar/archistar-smc
 * add PerformanceTest output for archistar 0.11
 * Change PerformanceTest data block sizes
 * Cevallo should follow the style of other Algorithms
 * restructure code and introduce CryptoEngine
 * overwork class hierarchy (data structures, ic, serialization)
 * fixup: seems I forgot to mvn clean;compile;test
 * work a bit on CevallosEngine test-case
 * also adopt rabin-ben-or test cases
 * fix faulty test cases
 * Overwork data-shares and unit tests
 * RabinBenOr doesn't need BerlekampWelch Decoder
 * "fix" shortened mac helper
 * switch from flexiprovider to bouncycastle
 * Merge pull request #18 from andreashappe/master
 * work a bit on polyhash
 * Merge branch 'master' of https://github.com/andreashappe/archistar-smc
 * move GF-math from static into instance methods
 * try to make GF-handling more consistent
 * abstract math implementation and split bc from handmade gf(2^8)
 * start with gf(257) implementatio
 * import generic Polynom-Division from bouncy castle
 * move PolyHash to normal int operations
 * Merge pull request #20 from andreashappe/gf_257
 * refactoring / style fixes
 * wip: work on gf(2^257)
 * wip: make gf(257) work with rabinIDS+erasure deocoder
 * fix: berlekamp-welch with gf(257) and optimizations
 * Merge pull request #22 from andreashappe/master
 * Merge branch 'stricter-GF256-tests' of https://github.com/jcflack/archistar-smc into jcflack-stricter-GF256-tests
 * Merge branch 'jcflack-stricter-GF256-tests'
 * fix whitespaces
 * start with fft/ntt implementation
 * fix whitespace errors
 * add a simple test case
 * move ntt classes into a package of their own
 * fix: division in GF(257)
 * add byte -> gf(256/257) converter
 * Merge branch 'master' of https://github.com/archistar/archistar-smc
 * start with NTT-based encoder/decoder
 * work on gf(257) / ntt
 * chg: update Changelog (and add what we were doing lately)
 * update Changelog to be more markdown-y
 * start with moving NTTShamir code into business logic
 * implement a NTT-based shamir-PSS algorithm
 * move NTTShamir performance tests into a sep. unit test
 * add: NTT-based RabinIDS
 * add ntt-dit2 based NTT
 * small fixes (as well as performance fixes)
 * move common rabin/shamir code paths into base classes
 * Lots of clean-ups, remove CevallosEngine
 * Unify the different Share types
 * merge KrawcywkShare & Share, refactor share unit tests
 * Merge NTT tests into secret-sharing performance tests
 * Add some performance optimizations
 * Improve test output and ''refactoring''
 * refactor information checking (and assorted tests)
 * refactor information checking (and assorted tests)
 * update documentation
 * Merge branch 'master' of https://github.com/archistar/archistar-smc
 * work on documentation and test output
 * improve documentation and tighten checkstyle
 * reduce cyclomatic complexity
 * make exception constructor public
 * fix: (smallish) encoding errors
 * Add a simple Shamir Secret-Sharing Engine
 * add ShamirEngine to performance tests
 * Merge pull request #24 from effweh-ait/master
 * Merge pull request #25 from effweh-ait/master
 * remove GF(257) and NTT, add Krawcyk-Engine
 * remove dynamic math-model (GF) selection
 * make StaticOutputEncoder like as ByteArrayOutputStream
 * remove some convertes, switch to byte[][], chnage (+256) into (&ff)
 * Update performance stats
 * Update README.md
 * Update performance stats
 * Update README.md
 * Merge pull request #26 from effweh-ait/purify
 * we're java8 only by now
 * Merge pull request #27 from effweh-ait/purify
 * Merge branch 'master' of github.com:Archistar/archistar-smc into purify
 * Merge branch 'purify' of github.com:Archistar/archistar-smc into purify
 * update performance numbers for 'purify'

Chapman Flack (1):

 * More thorough GF256 tests and one resulting fix.

Florian Wohner (35):

 * linkXRef is not a valid element in checkstyle:check
 * add IntelliJ files to .gitignore
 * project-wide whitespace cleanup
 * fix rabin ids and krawczyk css not returning smaller arrays; add tests Rabin (and therefore Krawczyk) should return arrays of size ceil(original_length/k) but in fact returned arrays of size original_length padded with lots of zeroes. this is now fixed, but the fix is complicated by the fact that we possibly also use block ciphers that use 16 byte blocks (and also add an extra block at the end)
 * fix test to correctly calculate size of shares (and add another test) once again that thing with the block ciphers; added a test using a ChaCha20 stream cipher
 * a little optimization to the block ciphers to only truncate arrays when necessary
 * implement new on-disk format for shares
 * permit empty files again, but check and convert nulls; add test
 * increment version number
 * document share format
 * add two small UML diagrams (PlantUML syntax)
 * add rationale for current on-disk format
 * add partial reconstruction option
 * add a (generated, then edited) overview class diagram
 * change reconstructPartial interface; better test this adds a parameter to the method to indicate the starting point of the partial share (relative to the original data); this is then passed through to the cipher. and make the test for reconstruction more thorough
 * use concrete types for engines in krawczyk
 * get rid of intermediary coefficient arrays for GeometricSecretSharing pull implementation of share(byte[][], byte[]) down into concrete classes
 * parallelize rabin; we need Java 8 now
 * use one-stage look-up tables for sharing
 * directly return yValues in Share::getSerializedData when not using IC
 * enable information checking in Shamir engine; tests add stern warning when doing partial reconstruction
 * bump version in preparation of interface changes
 * bump share version in preparation of interface changes
 * refactor Shares to support fingerprinting; rename engines
 * restore partial reconstruction test for CSS engine
 * add corruption tests for CSS engine
 * hide stuff behind a factory
 * adjust serialized.md to changes
 * adjust serialized.md to changes
 * CryptoEngines now return a ReconstructionResult also collect shares that did not pass validation
 * remove ReconstructionException from the CryptoEngine interface
 * adapt Shares class diagram to recent changes
 * adapt overall class diagram to recent changes
 * adapt sequence diagram to recent changes
 * add possibility to CSS to have all generated keys encrypted

Thomas Lorünser (2):

 * Update README.md
 * Create README.md
 * First rudementary fix for NTT. More refactoring is necessary to use correct nth primitive root of unity.

Version 0.1
===========


Andreas Happe (39):

* remove some compile warnings
* run code through netbeans source formatter
* Merge pull request #6 from efrantar-tgm/math
* Merge pull request #8 from efrantar-tgm/test
* Merge pull request #7 from efrantar-tgm/random
* Merge pull request #9 from efrantar-tgm/exceptions
* Merge pull request #10 from efrantar-tgm/shares
* Merge pull request #11 from efrantar-tgm/decoder
* Merge pull request #13 from efrantar-tgm/code_improvement
* Merge pull request #14 from gye-tgm/master
* Update .travis.yml
* Update .travis.yml
* Merge pull request #15 from gye-tgm/cevallos
* add and enforce checkstyle
* add and enforce findbugs in compile-phase
* bump findbugs version, should work with java8 now
* switch Decoder to a factory pattern
* start on refactoring testcases
* Decoder: throw exception instead of returning 0 if not solvable
* Merge branch 'master' into testcases
* fix: errors that I've introduced with the factory pattern
* Merge pull request #16 from gye-tgm/master
* move ShareHelper into Shares and Algorithms
* bump bouncy castle from 1.46 to 1.51
* WIP: actually use bouncycastle
* chg: refactor symmetric crypto
* chg: add rng.fillBytes
* fix: rename variable to quieten formatting warning
* test cases should use the same MAC/rng
* unify RandomSource usage and introduce BCDigestRandom
* introduce MacHelper interface and clean-up API
* overwork MAC subsystem
* let helpers tell the needed keysize; improve debug output
* add an initial Changelog
* update Changelog
* update readme.md with performance numbers
* move documentation into docs/
* Add more algorithms to PerformanceTest
* bump pom.xml Version to 0.1


Elias Frantar (39):

* removed dependency from GF256's gf256
* added documentation
* replaced asserts with a condition throwing an ArithmeticException if violated
* GF256 is now using (for now hardcoded) lookup-tables for calculation
* create a custom GF256Polynomial which uses the fast arithmetic operations from GF256 for evaluateAt()
* added unit-tests for GF256 to allow easier testing of further optimizations (+ typo fix in performance.txt)
* lookup-tables not hardcoded anymore (+ add '{}')
* added newlines at end of files
* added some more documentation to RandomSource (+ deleted JavaRandomSource)
* added SHA1-PRNG
* added CTR-PRNG
* added Stream-PRNG and bouncy-castle dependency to pom.xml
* added a simple unit-test for performance comparison of the different PRNGs
* fixed code formatting
* added simple unit-test for GF256Polynomial
* added new test-cases
* moved TestMAC into sub-package
* now throwing Impossible-Exceptions
* Merge branch 'random'
* moved Exceptions into sub-package
* added a CryptoException and updated Exception-documentation
* SecretSharing now throwing ReconstructionExceptions
* improved Exception-handling
* Merge branch 'master' of https://github.com/Archistar/archistar-smc into exceptions
* implemented new share structure
* everything now working with new shares
* added documentation to RabinBenOrShare
* moved decoder to individual class
* implemented BerlekampWelch decoder
* Shamir and RabinIDS now using PolySolver
* deleted now unnecessary class PolyGF256
* improved code and documentation of ShamirPSS
* improved code and documentation of RabinIDS
* improved code and documentation of KrawczykCSS
* added safeCast() to Krawczyk
* improved some documentation and formatting
* fixed minor formatting errors
* readded checkForZeros()
* implemented CevallosUSRSS

Gary Ye (10):

* Two logical errors: the points were not distinct and the number of faulty points can be less than wanted. Fixed this by generating random and distinct integers with a helper method.
* The numbers will be increased in range [1, 255] now.
* Adjusted the gitignore files to ignore eclipse and OS X meta files.
* Fixed a boundary check bug.
* Saved a little bit memory.
* Changed the elimination round algorithm from O(n^3) to O(n^2)
* Formatted and using queue
* Removed the try and catch block which caused the error.
* Parameterized  EncryptionAlgorithm and added test
* Commented out bug


Version 0.0.3 (2014-04-30)
==========================

Andreas Happe (14):

* update readme.md
* fix: use AES with padding
* chg: improve ShareSerializer
* add simple Shamir Secret Sharing to documentation
* fix: github does not understand markdown tables..
* add a comment about subtraction within GF(2^8)
* introduce ImpossibleException.
* add links to finite field arithmetic
* Merge pull request #4 from cyzhao/master
* update performance test
* chg: also output bandwith numbers for performance test
* fix: allow 0^k for RabinIDS as source data
* fix: correct identation and remove unused variable
* chg: bump version to 0.0.3

Charles Zhao (2):

* Downgraded java version to 1.6 for broader audience. Updated fest-assert-core dependency to test scope.
* Removed accidental checkin of eclipse project files .


Version 0.0.2 (2013-11-06)
==========================

Andreas Happe (2):

* add travis configuration
* new snapshot version


Version 0.0.1 (2013-11-06)
==========================

Andreas Happe (1):

* add initial crypto algorithms

Thomas Lorünser (1):

* Initial commit


Version 0.0.0
=============

Franca-Sofia Fehrenbach wrote an initial prototype. It was not incorporated
into the current software project in its then form ao I am adding this so
that her contributions are not forgotten.
