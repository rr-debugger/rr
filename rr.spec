Buildroot: @CPACK_BINARY_DIR@/_CPack_Packages/@CPACK_SYSTEM_NAME@/RPM/@CPACK_PACKAGE_FILE_NAME@
Summary:        Lightweight tool for recording and replaying execution of applications (trees of processes and threads)
Name:           @CPACK_PACKAGE_NAME@
Version:        @CPACK_PACKAGE_VERSION@
Release:        @CPACK_RPM_PACKAGE_RELEASE@
License:        @CPACK_RPM_PACKAGE_LICENSE@
Group:          Development/Debuggers
Vendor:         @CPACK_PACKAGE_VENDOR@
Prefix:         @CPACK_PACKAGING_INSTALL_PREFIX@
@CPACK_RPM_PACKAGE_REQUIRES@

%define _rpmfilename @CPACK_PACKAGE_FILE_NAME@.rpm
%define _unpackaged_files_terminate_build 0
 
%description
rr is a lightweight tool for recording and replaying execution of applications (trees of processes and threads).  For more information, please visit

http://rr-project.org
 
# This is a shortcutted spec file generated by CMake RPM generator
# we skip _install step because CPack does that for us.
# We do only save CPack installed tree in _prepr
# and then restore it in build.

%files
%defattr(-,root,root,-)
@CPACK_PACKAGING_INSTALL_PREFIX@/lib64/*
@CPACK_PACKAGING_INSTALL_PREFIX@/bin/rr
@CPACK_PACKAGING_INSTALL_PREFIX@/bin/rr_exec_stub*
@CPACK_PACKAGING_INSTALL_PREFIX@/bin/signal-rr-recording.sh
@CPACK_PACKAGING_INSTALL_PREFIX@/share/rr/*.xml

%changelog
* Tue Jun 25 2013 Chris Jones <cjones@triton> - 
- Initial build.
