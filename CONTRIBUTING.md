Animecoin patch writing guidelines
====================

General
---------------------
- Fork the master repository, make changes to your repository, create a pull request.
- Try following the Bitcoin Core code style for the ease of backporting.
- Do not forget to keep the .pro file up to date with your changes, too.

Obsolete language features
---------------------
Submitted C++ code should be at the very least C++11 compliant.
Boost dependency is a subject to be removed eventually. No new features should use Boost. Regarding modification of existing features, see below.

- NULL is deprecated. For C++ pointers, use nullptr. For C, use 0.
- throw() in function declarations should be changed to noexcept.
- [0] should migrate to .data() where applicable.

Boost features that are mostly search-and-replace-upgradeable
---------------------
- boost::function -> std::function
- boost::scoped_ptr -> std::unique_ptr
- boost::call_once -> std::call_once
- BOOST_FOREACH (..., ...) -> for (... : ...)
- boost::unordered_map -> std::unordered_map, boost_unordered_node -> unordered_node
- boost::thread::hardware_concurrency -> std::thread::hardware_concurrency (since boost 1.56, older boost versions return HT cores)
- boost::assign::list_of, boost::assign::map_list_of -> curly braces initialization

Boost features that should be removed soon
---------------------
- Boost threading primitives. Since Boost threads are interruptible and std ones aren't, this should not be done mindlessly.
- boost::bind -> std::bind
- boost::random
- boost::program_options

Obsolete software features
---------------------
- OpenSSL is a subject to be removed entirely. No new features should use OpenSSL.
- BIP70 is dropped by upstream and should be forgotten.
- As a consequence, protobuf becomes an undesired dependency. New features relying on protobuf will not be accepted.

Features no longer requiring OpenSSL
---------------------
- Elliptic curve checking in the main code.
- AES.

Features still using OpenSSL
---------------------
- RNG. Requires more code uplifting to migrate.

Features that should not be backported
---------------------
Head developers agreed on the following upstream features not fitting the Animecoin concept:
- Modal overlay.
- Any features that forcibly propagate deprecation of address reuse.

Qt-exclusive keywords, such as signal/slot/emit, Qt foreach etc should be left intact for the time being.

Subtrees
---------------------
- libsecp256k1 should be kept fresh and tested on update.
- leveldb should be tested extensively before pulling an update, as it's entwined tightly with network consensus.
