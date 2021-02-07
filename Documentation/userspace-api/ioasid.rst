.. SPDX-License-Identifier: GPL-2.0
.. ioasid:

=====================================
IOASID Userspace API
=====================================

The IOASID UAPI is used for userspace IOASID allocation/free requests,
thus IOASID management is centralized in the IOASID core[1] in the kernel. The
primary use case is guest Shared Virtual Address (SVA) today.

Requests such as allocation/free can be issued by the users and managed
on a per-process basis through the ioasid core. Upon opening ("/dev/ioasid"),
a process obtains a unique handle associated with the process's mm_struct.
This handle is mapped to an FD in the userspace. Only a single open is
allowed per process.

File descriptors can be transferred across processes by employing fork() or
UNIX domain socket. FDs obtained by transfer cannot be used to perform
IOASID requests. The following behaviors are recommended for the
applications:

 - forked children close the parent's IOASID FDs immediately, open new
   /dev/ioasid FDs if IOASID allocation is desired

 - do not share FDs via UNIX domain socket, e.g. via sendmsg

================
Userspace APIs
================

/dev/ioasid provides below ioctls:

*) IOASID_GET_API_VERSION: returns the API version, userspace should check
   the API version first with the one it has embedded.
*) IOASID_GET_INFO: returns the information on the /dev/ioasid.
   - ioasid_bits: the ioasid bit width supported by this uAPI, userspace
     should check the ioasid_bits returned by this ioctl with the ioasid
     bits it wants and should fail if it's smaller than the one that
     userspace wants, otherwise, allocation will be failed.
*) IOASID_REQUEST_ALLOC: returns an IOASID which is allocated in kernel within
   the specified ioasid range.
*) IOASID_REQUEST_FREE: free an IOASID per userspace's request.

For detailed definition, please see include/uapi/linux/ioasid.h.

.. contents:: :local:

[1] Documentation/driver-api/ioasid.rst
