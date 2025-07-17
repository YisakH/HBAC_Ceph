# Ceph with Hierarchical-Based Access Control (HBAC)

This project is an extended version of the open-source distributed storage system, Ceph, with Hierarchical-Based Access Control (HBAC).

## Introduction

This repository is based on the official Ceph functionality and has been extended to allow the application of granular access control policies according to various hierarchies within an organization (e.g., departments, teams, user groups, etc.). It provides all the features of the existing Ceph, with the addition of HBAC policy management and enforcement capabilities.

## Key Features

-   Support for Hierarchical-Based Access Control (HBAC)
-   100% compatibility with existing Ceph
-   Enhanced policy-based data access control and auditing

---

## Build Prerequisites

Make sure that ``curl`` is installed. The Debian and Ubuntu ``apt`` command is
provided here, but if you use a system with a different package manager, then
you must use whatever command is the proper counterpart of this one:

    apt install curl

Install Debian or RPM package dependencies by running the following command:

	./install-deps.sh

Install the ``python3-routes`` package:

    apt install python3-routes


## Building Ceph

These instructions are meant for developers who are compiling the code for
development and testing. To build binaries that are suitable for installation
we recommend that you build `.deb` or `.rpm` packages, or refer to
``ceph.spec.in`` or ``debian/rules`` to see which configuration options are
specified for production builds.

To build Ceph, make sure that you are in the top-level `ceph` directory that
contains `do_cmake.sh` and `CONTRIBUTING.rst` and run the following commands:

	./do_cmake.sh
	cd build
	ninja

``do_cmake.sh`` by default creates a "debug build" of Ceph, which can be up to
five times slower than a non-debug build.  Pass
``-DCMAKE_BUILD_TYPE=RelWithDebInfo`` to ``do_cmake.sh`` to create a non-debug
build.

[Ninja](https://ninja-build.org/) is the buildsystem used by the Ceph project
to build test builds.  The number of jobs used by `ninja` is derived from the
number of CPU cores of the building host if unspecified. Use the `-j` option to
limit the job number if the build jobs are running out of memory. If you
attempt to run `ninja` and receive a message that reads `g++: fatal error:
Killed signal terminated program cc1plus`, then you have run out of memory.
Using the `-j` option with an argument appropriate to the hardware on which the
`ninja` command is run is expected to result in a successful build. For example,
to limit the job number to 3, run the command `ninja -j 3`. On average, each
`ninja` job run in parallel needs approximately 2.5 GiB of RAM.

This documentation assumes that your build directory is a subdirectory of the
`ceph.git` checkout. If the build directory is located elsewhere, point
`CEPH_GIT_DIR` to the correct path of the checkout. Additional CMake args can
be specified by setting ARGS before invoking ``do_cmake.sh``.  See [cmake
options](#cmake-options) for more details. For example:

    ARGS="-DCMAKE_C_COMPILER=gcc-7" ./do_cmake.sh

To build only certain targets, run a command of the following form:

	ninja [target name]

To install:

	ninja install
 
### CMake Options

The `-D` flag can be used with `cmake` to speed up the process of building Ceph
and to customize the build.

#### Building without RADOS Gateway

The RADOS Gateway is built by default. To build Ceph without the RADOS Gateway,
run a command of the following form:

	cmake -DWITH_RADOSGW=OFF [path to top-level ceph directory]

#### Building with debugging and arbitrary dependency locations 

Run a command of the following form to build Ceph with debugging and alternate
locations for some external dependencies:

	cmake -DCMAKE_INSTALL_PREFIX=/opt/ceph -DCMAKE_C_FLAGS="-Og -g3 -gdwarf-4" \
	..

Ceph has several bundled dependencies such as Boost, RocksDB and Arrow. By
default, `cmake` builds these bundled dependencies from source instead of using
libraries that are already installed on the system. You can opt to use these
system libraries, as long as they meet Ceph's version requirements. To use
system libraries, use `cmake` options like `WITH_SYSTEM_BOOST`, as in the
following example:

	cmake -DWITH_SYSTEM_BOOST=ON [...]

To view an exhaustive list of -D options, invoke `cmake -LH`:

	cmake -LH

#### Preserving diagnostic colors

If you pipe `ninja` to `less` and would like to preserve the diagnostic colors
in the output in order to make errors and warnings more legible, run the
following command:  

	cmake -DDIAGNOSTICS_COLOR=always ...

The above command works only with supported compilers.

The diagnostic colors will be visible when the following command is run: 

	ninja | less -R

Other available values for `DIAGNOSTICS_COLOR` are `auto` (default) and
`never`.


## Building a source tarball

To build a complete source tarball with everything needed to build from
source and/or build a (deb or rpm) package, run

	./make-dist

This will create a tarball like ceph-$version.tar.bz2 from git.
(Ensure that any changes you want to include in your working directory
are committed to git.)


## Running a test cluster

From the `ceph/` directory, run the following commands to launch a test Ceph
cluster:

	cd build
	ninja vstart        # builds just enough to run vstart
	../src/vstart.sh --debug --new -x --localhost --bluestore
	./bin/ceph -s

Most Ceph commands are available in the `bin/` directory. For example:

	./bin/rbd create foo --size 1000
	./bin/rados -p foo bench 30 write

To shut down the test cluster, run the following command from the `build/`
directory:

	../src/stop.sh

Use the sysvinit script to start or stop individual daemons: 

	./bin/init-ceph restart osd.0
	./bin/init-ceph stop


## Running unit tests

To build and run all tests (in parallel using all processors), use `ctest`:

	cd build
	ninja
	ctest -j$(nproc)

(Note: Many targets built from src/test are not run using `ctest`.
Targets starting with "unittest" are run in `ninja check` and thus can
be run with `ctest`. Targets starting with "ceph_test" can not, and should
be run by hand.)

When failures occur, look in build/Testing/Temporary for logs.

To build and run all tests and their dependencies without other
unnecessary targets in Ceph:

	cd build
	ninja check -j$(nproc)

To run an individual test manually, run `ctest` with -R (regex matching):

	ctest -R [regex matching test name(s)]

(Note: `ctest` does not build the test it's running or the dependencies needed
to run it)

To run an individual test manually and see all the tests output, run
`ctest` with the -V (verbose) flag:

	ctest -V -R [regex matching test name(s)]

To run tests manually and run the jobs in parallel, run `ctest` with 
the `-j` flag:

	ctest -j [number of jobs]

There are many other flags you can give `ctest` for better control
over manual test execution. To view these options run:

	man ctest


## Building the Documentation

### Prerequisites

The list of package dependencies for building the documentation can be
found in `doc_deps.deb.txt`:

	sudo apt-get install `cat doc_deps.deb.txt`

### Building the Documentation

To build the documentation, ensure that you are in the top-level
`/ceph` directory, and execute the build script. For example:

	admin/build-doc

## Reporting Issues

To report an issue and view existing issues, please visit https://tracker.ceph.com/projects/ceph.
