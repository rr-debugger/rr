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

%define _rpmdir @CPACK_BINARY_DIR@/_CPack_Packages/@CPACK_SYSTEM_NAME@/RPM
%define _rpmfilename @CPACK_PACKAGE_FILE_NAME@.rpm
%define _unpackaged_files_terminate_build 0
%define _topdir @CPACK_BINARY_DIR@/_CPack_Packages/@CPACK_SYSTEM_NAME@/RPM
 
%description
rr is a lightweight tool for recording and replaying execution of applications (trees of processes and threads).  For more information, please visit

http://mozilla.github.com/rr
 
# This is a shortcutted spec file generated by CMake RPM generator
# we skip _install step because CPack does that for us.
# We do only save CPack installed tree in _prepr
# and then restore it in build.
%prep
mv $RPM_BUILD_ROOT @CPACK_BINARY_DIR@/_CPack_Packages/@CPACK_SYSTEM_NAME@/RPM/tmpBBroot
 
%install
if [ -e $RPM_BUILD_ROOT ];
then
  rm -Rf $RPM_BUILD_ROOT
fi
mv "@CPACK_BINARY_DIR@/_CPack_Packages/@CPACK_SYSTEM_NAME@/RPM/tmpBBroot" $RPM_BUILD_ROOT
 
%files
%defattr(-,root,root,-)
@CPACK_PACKAGING_INSTALL_PREFIX@/lib/*
@CPACK_PACKAGING_INSTALL_PREFIX@/bin/rr
 
%changelog
* Tue Jun 25 2013 Chris Jones <cjones@triton> - 
- Initial build.
