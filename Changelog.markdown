Version 0.2
===========

WIP:

* switch from flexiprovider to bouncy-castle (which would include
  the same library anyways)
* drop support for java 1.6 -- it's not maintained anymore
* restructure class hierarchy
* introduce CevallosEngine and RabinBenOrEngine, those two provide
  a very simple high-level interface for working with archistar-smc*
* make mathematic helper modular and introduce different implementations.
  this reduces performance for now but should lead to a cleaner
	implementation in the long term
* introduce GF(257) mathematics. This was needed for the also newly
  introduced NTT-based encoder/decoders

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
